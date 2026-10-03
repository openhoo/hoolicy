package strictjson

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDecodePreservesNumbersAndRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`null`, `[]`, `{}`, `{"large":18446744073709551615,"decimal":1.25}`, `[true,false,"text",null]`} {
		decoder := json.NewDecoder(strings.NewReader(input))
		decoder.UseNumber()
		var expected any
		if err := decoder.Decode(&expected); err != nil {
			t.Fatal(err)
		}
		actual, err := Decode([]byte(input))
		if err != nil || !reflect.DeepEqual(actual, expected) {
			t.Errorf("%s: got %#v error %v, expected %#v", input, actual, err, expected)
		}
	}
	for _, input := range []string{`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `[{"a":1,"a":2}]`, `{} {}`, `{"a":}`, `{"a":1]`, `[[}`, strings.Repeat("[", 514) + "0" + strings.Repeat("]", 514)} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Errorf("invalid or ambiguous input accepted: %s", input)
		}
	}
}

func FuzzDecodeMatchesStandardJSONForAcceptedInputs(f *testing.F) {
	f.Add([]byte(`{"ok":[1,true,null]}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		actual, err := Decode(input)
		if err != nil {
			return
		}
		decoder := json.NewDecoder(strings.NewReader(string(input)))
		decoder.UseNumber()
		var expected any
		if err := decoder.Decode(&expected); err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("accepted input disagrees with standard JSON: %q, %v", input, err)
		}
	})
}
