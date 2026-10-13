package celenv

import (
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/overloads"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/interpreter"
)

const guardedMembershipOverload = "hoolicy_guarded_membership"

// CEL's built-in equality and membership costs only see the outer container.
// Shared nested lists can therefore do millions of comparisons at little cost.
// Count the values actually compared, stop within one call, and charge that
// traversal to the evaluation's cost tracker as well. Each call owns its
// counter; compiled programs remain safe to reuse concurrently.
type comparisonBudget struct {
	work, limit uint64
}

func cancelCost() {
	panic(interpreter.EvalCancelledError{Cause: interpreter.CostLimitExceeded, Message: "operation cancelled: actual cost limit exceeded"})
}

func (budget *comparisonBudget) charge(work uint64) {
	if work > budget.limit-budget.work {
		cancelCost()
	}
	budget.work += work
}

// equal follows CEL's heterogeneous container equality, including its early
// exits. Count container visits even when they contain no scalar leaves.
func (budget *comparisonBudget) equal(lhs, rhs ref.Val, depth int) ref.Val {
	budget.charge(1)
	if depth > 256 {
		cancelCost()
	}
	switch left := lhs.(type) {
	case traits.Lister:
		right, ok := rhs.(traits.Lister)
		if !ok || left.Size() != right.Size() {
			return types.False
		}
		for index := types.IntZero; index < left.Size().(types.Int); index++ {
			if budget.equal(left.Get(index), right.Get(index), depth+1) == types.False {
				return types.False
			}
		}
		return types.True
	case traits.Mapper:
		right, ok := rhs.(traits.Mapper)
		if !ok || left.Size() != right.Size() {
			return types.False
		}
		for iterator := left.Iterator(); iterator.HasNext() == types.True; {
			key := iterator.Next()
			leftValue, _ := left.Find(key)
			rightValue, found := right.Find(key)
			if !found || budget.equal(leftValue, rightValue, depth+1) == types.False {
				return types.False
			}
		}
		return types.True
	default:
		// Retain CEL's proportional string/byte comparison charge when these
		// values occur inside a list or map; scalar operations keep CEL's own
		// tracker below.
		var size uint64
		switch value := lhs.(type) {
		case types.String:
			if other, ok := rhs.(types.String); ok {
				size = uint64(min(len(value), len(other)))
			}
		case types.Bytes:
			if other, ok := rhs.(types.Bytes); ok {
				size = uint64(min(len(value), len(other)))
			}
		}
		if size > 10 {
			budget.charge((size - 1) / 10)
		}
		return types.Equal(lhs, rhs)
	}
}

func structural(value ref.Val) bool {
	_, list := value.(traits.Lister)
	_, object := value.(traits.Mapper)
	return list || object
}

func structuralCall(call interpreter.InterpretableCall, limit uint64) interpreter.InterpretableCall {
	// A dyn-typed in expression may have no resolved overload ID. Its runtime
	// value can still be a list, so dispatch by function name and use one
	// private overload ID for charging both statically and dynamically typed
	// membership calls.
	if call.Function() == operators.In {
		return interpreter.NewCall(call.ID(), call.Function(), guardedMembershipOverload, call.Args(), func(args ...ref.Val) ref.Val {
			budget := comparisonBudget{limit: limit}
			return budget.contains(args[0], args[1])
		})
	}
	switch call.OverloadID() {
	case overloads.Equals, overloads.NotEquals:
		return interpreter.NewCall(call.ID(), call.Function(), call.OverloadID(), call.Args(), func(args ...ref.Val) ref.Val {
			budget := comparisonBudget{limit: limit}
			result := budget.equal(args[0], args[1], 0)
			if call.OverloadID() == overloads.NotEquals {
				return types.Bool(result != types.True)
			}
			return result
		})
	}
	return nil
}

func (budget *comparisonBudget) contains(element, container ref.Val) ref.Val {
	list, ok := container.(traits.Lister)
	if !ok {
		if aggregate, ok := container.(traits.Container); ok {
			return aggregate.Contains(element)
		}
		return types.ValOrErr(container, "no such overload")
	}
	for iterator := list.Iterator(); iterator.HasNext() == types.True; {
		if budget.equal(element, iterator.Next(), 0) == types.True {
			return types.True
		}
	}
	return types.False
}

func trackComparison(limit uint64) interpreter.FunctionTracker {
	return func(args []ref.Val, _ ref.Val) *uint64 {
		if len(args) != 2 || !structural(args[0]) || types.IsUnknownOrError(args[0]) || types.IsUnknownOrError(args[1]) {
			return nil
		}
		budget := comparisonBudget{limit: limit}
		budget.equal(args[0], args[1], 0)
		return &budget.work
	}
}

func trackMembership(limit uint64) interpreter.FunctionTracker {
	return func(args []ref.Val, _ ref.Val) *uint64 {
		if len(args) != 2 || types.IsUnknownOrError(args[0]) || types.IsUnknownOrError(args[1]) {
			return nil
		}
		if _, list := args[1].(traits.Lister); !list {
			cost := uint64(1)
			return &cost
		}
		budget := comparisonBudget{limit: limit}
		budget.contains(args[0], args[1])
		// CEL charges the outer list's size even for an early match.
		budget.work = max(budget.work, listSize(args[1]))
		return &budget.work
	}
}

func distinctBound(args []ref.Val, limit uint64) uint64 {
	base := selfCompareBound(0)(args, limit)
	if base > limit || len(args) == 0 {
		return base
	}
	list, ok := args[0].(traits.Lister)
	if !ok {
		return base
	}
	budget := comparisonBudget{limit: limit}
	unique := make([]ref.Val, 0, listSize(list))
	for iterator := list.Iterator(); iterator.HasNext() == types.True; {
		element := iterator.Next()
		seen := false
		for _, other := range unique {
			if budget.equal(element, other, 0) == types.True {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, element)
		}
	}
	return max(base, budget.work)
}

func trackDistinct(limit uint64) interpreter.FunctionTracker {
	return func(args []ref.Val, _ ref.Val) *uint64 {
		if len(args) == 0 || types.IsUnknownOrError(args[0]) {
			return nil
		}
		cost := 10 + distinctBound(args, limit)
		return &cost
	}
}

func trackFlatten(limit uint64) interpreter.FunctionTracker {
	return func(args []ref.Val, _ ref.Val) *uint64 {
		cost := 10 + flattenBound(args, limit)
		return &cost
	}
}
