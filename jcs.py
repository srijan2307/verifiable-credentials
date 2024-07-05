import json
import math

class CanonicalJSONEncoder(json.JSONEncoder):
    def __init__(self, *args, **kwargs):
        super().__init__(
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            *args,
            **kwargs
        )

    def default(self, obj):
        if isinstance(obj, float):
            # Handle special float values
            if math.isnan(obj):
                return "NaN"
            elif math.isinf(obj):
                return "Infinity" if obj > 0 else "-Infinity"
            else:
                # Format floats consistently
                return format(obj, ".17g")
        else:
            return super().default(obj)

    def encode(self, obj):
        # Encode the object to JSON
        json_str = super().encode(obj)
        # Remove whitespace
        return "".join(json_str.split())

# Get JSON data from the user
json_data = input("Enter JSON data: ")

try:
    # Parse JSON data
    data = json.loads(json_data)

    # Encode JSON data using the canonical encoder
    canonical_json = CanonicalJSONEncoder().encode(data)

    print("Canonical JSON:")
    print(canonical_json)

except json.JSONDecodeError:
    print("Invalid JSON format. Please enter valid JSON data.")
