package celenv

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/functions"
	"cel.dev/cel-go/common/overloads"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/interpreter"
)

// guardedFunctions are extension functions whose allocation or running time
// grows with their output, or quadratically with their input. CEL charges a
// call's cost only after it returns, so without a pre-call bound one call can
// allocate gigabytes or run for minutes before costLimit is checked, and
// rule interrupts are observed only between comprehension steps.
var guardedFunctions = []string{"flatten", "distinct", "sort", "@sortByAssociatedKeys", "join", "replace", "format"}

// ProgramOptions keeps allocating extension calls and structural comparisons
// within limit before they finish. Custom trackers charge nested traversals
// and rendered strings so repeated individually bounded calls also consume
// the evaluation's shared cost budget.
func ProgramOptions(environment *cel.Env, limit uint64) ([]cel.ProgramOption, error) {
	bindings := map[string]*functions.Overload{}
	declarations := environment.Functions()
	for _, name := range guardedFunctions {
		declaration, exists := declarations[name]
		if !exists {
			return nil, fmt.Errorf("CEL extension function %s is not declared", name)
		}
		overloads, err := declaration.Bindings()
		if err != nil {
			return nil, err
		}
		for _, overload := range overloads {
			bindings[overload.Operator] = overload
		}
	}
	decorator := func(node interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		call, ok := node.(interpreter.InterpretableCall)
		if !ok {
			return node, nil
		}
		if guarded := structuralCall(call, limit); guarded != nil {
			return guarded, nil
		}
		bound := guardedBound(call.Function())
		if bound == nil {
			return node, nil
		}
		overload := bindings[call.OverloadID()]
		if overload == nil {
			overload = bindings[call.Function()]
		}
		if overload == nil {
			return nil, fmt.Errorf("CEL extension %s has no binding for %s", call.Function(), call.OverloadID())
		}
		return interpreter.NewCall(call.ID(), call.Function(), call.OverloadID(), call.Args(), func(args ...ref.Val) ref.Val {
			if bound(args, limit) > limit {
				panic(interpreter.EvalCancelledError{Cause: interpreter.CostLimitExceeded, Message: "operation cancelled: actual cost limit exceeded"})
			}
			return invoke(overload, args)
		}), nil
	}
	return []cel.ProgramOption{
		cel.CustomDecoratorV2(decorator),
		cel.CostTrackerOptions(
			interpreter.OverloadCostTracker("string_format", trackFormat),
			interpreter.OverloadCostTracker(overloads.Equals, trackComparison(limit)),
			interpreter.OverloadCostTracker(overloads.NotEquals, trackComparison(limit)),
			interpreter.OverloadCostTracker(guardedMembershipOverload, trackMembership(limit)),
			interpreter.OverloadCostTracker("list_distinct", trackDistinct(limit)),
			interpreter.OverloadCostTracker("list_flatten", trackFlatten(limit)),
			interpreter.OverloadCostTracker("list_flatten_int", trackFlatten(limit)),
		),
	}, nil
}

// invoke calls an extension binding as the planner would, including its
// operand-trait dispatch check for singleton bindings.
func invoke(overload *functions.Overload, args []ref.Val) ref.Val {
	if overload.OperandTrait != 0 && !args[0].Type().HasTrait(overload.OperandTrait) {
		return types.NewErr("no such overload: %s", overload.Operator)
	}
	switch {
	case len(args) == 1 && overload.Unary != nil:
		return overload.Unary(args[0])
	case len(args) == 2 && overload.Binary != nil:
		return overload.Binary(args[0], args[1])
	case overload.Function != nil:
		return overload.Function(args...)
	}
	return types.NewErr("no such overload: %s", overload.Operator)
}

type costBound func(args []ref.Val, limit uint64) uint64

// guardedBound returns a lower bound of the cost CEL charges for the call
// once it returns. Each bound stops counting as soon as it exceeds limit.
func guardedBound(function string) costBound {
	switch function {
	case "flatten":
		return flattenBound
	case "distinct":
		return distinctBound
	case "sort":
		return selfCompareBound(0)
	case "@sortByAssociatedKeys":
		return selfCompareBound(1)
	case "join":
		return joinBound
	case "replace":
		return replaceBound
	case "format":
		return formatBound
	}
	return nil
}

func listSize(value ref.Val) uint64 {
	if list, ok := value.(traits.Lister); ok {
		if size, ok := list.Size().(types.Int); ok && size > 0 {
			return uint64(size)
		}
	}
	return 0
}

func runes(value ref.Val) uint64 {
	if text, ok := value.(types.String); ok {
		return uint64(utf8.RuneCountInString(string(text)))
	}
	return 0
}

// selfCompareBound mirrors the O(n^2) charge for distinct, sort and sortBy.
func selfCompareBound(argument int) costBound {
	return func(args []ref.Val, _ uint64) uint64 {
		if len(args) <= argument {
			return 0
		}
		size := listSize(args[argument])
		if size > 1<<31 {
			return ^uint64(0)
		}
		return 2 * size * size
	}
}

// flattenBound counts the elements flatten would produce.
func flattenBound(args []ref.Val, limit uint64) uint64 {
	depth := int64(1)
	if len(args) == 2 {
		if value, ok := args[1].(types.Int); ok {
			depth = int64(value)
		}
	}
	var total uint64
	var count func(value ref.Val, depth int64)
	count = func(value ref.Val, depth int64) {
		total++
		list, ok := value.(traits.Lister)
		if !ok || depth < 0 {
			return
		}
		for iterator := list.Iterator(); iterator.HasNext() == types.True && total <= limit; {
			element := iterator.Next()
			if _, nested := element.(traits.Lister); nested && depth > 0 {
				count(element, depth-1)
			} else {
				total++
			}
		}
	}
	if len(args) > 0 && depth >= 0 {
		count(args[0], depth)
	}
	return total
}

// joinBound counts the runes join would produce.
func joinBound(args []ref.Val, limit uint64) uint64 {
	if len(args) == 0 {
		return 0
	}
	list, ok := args[0].(traits.Lister)
	if !ok {
		return 0
	}
	separator := uint64(0)
	if len(args) == 2 {
		separator = runes(args[1])
	}
	var total uint64
	for index, iterator := 0, list.Iterator(); iterator.HasNext() == types.True && total <= limit; index++ {
		if index > 0 {
			total += separator
		}
		total += runes(iterator.Next())
	}
	return total
}

// replaceBound counts the runes replace would produce.
func replaceBound(args []ref.Val, _ uint64) uint64 {
	if len(args) < 3 {
		return 0
	}
	text, ok1 := args[0].(types.String)
	old, ok2 := args[1].(types.String)
	replacement, ok3 := args[2].(types.String)
	if !ok1 || !ok2 || !ok3 {
		return 0
	}
	occurrences := int64(strings.Count(string(text), string(old)))
	if len(args) == 4 {
		if limit, ok := args[3].(types.Int); ok && int64(limit) >= 0 && int64(limit) < occurrences {
			occurrences = int64(limit)
		}
	}
	result := int64(runes(text)) + occurrences*(int64(runes(replacement))-int64(runes(old)))
	if result < 0 {
		return 0
	}
	return uint64(result)
}

// formatBound counts runes and scalar values that format renders from its
// arguments, following shared nested lists and maps.
func formatBound(args []ref.Val, limit uint64) uint64 {
	var total uint64
	var walk func(value ref.Val)
	walk = func(value ref.Val) {
		if total > limit {
			return
		}
		switch current := value.(type) {
		case types.String:
			// Empty strings still take time to visit and delimit in a rendered
			// list. Charging only their rune count lets shared nested lists of
			// empty strings bypass the pre-call guard by millions of elements.
			total += max(1, runes(current))
		case traits.Mapper:
			total++
			for iterator := current.Iterator(); iterator.HasNext() == types.True && total <= limit; {
				key := iterator.Next()
				walk(key)
				walk(current.Get(key))
			}
		case traits.Lister:
			total++
			for iterator := current.Iterator(); iterator.HasNext() == types.True && total <= limit; {
				walk(iterator.Next())
			}
		default:
			total++
		}
	}
	for _, argument := range args {
		walk(argument)
	}
	return total
}

// trackFormat charges string.format for traversing its format string and
// for the rendered result, so repeated formatting accumulates cost.
func trackFormat(args []ref.Val, result ref.Val) *uint64 {
	total := 1 + runes(args[0])/10 + runes(result)
	return &total
}
