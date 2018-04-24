import sys
import json
import shutil

def update(filepath):
	with open(filepath, "r") as f:
		shutil.copy(filepath, filepath + ".bak")
		spec = json.load(f)
		new_spec = {
			"input_filepath": "somepath.h",
			"datetime": 0,
			"enumerations": {},
			"attributes": {},
		}
		spec_name = spec["name"]
		new_spec["attributes"][spec_name] = {
			"original_name": spec["original_name"],
			"value_type": "u16",
			"items": {}
		}
		for item in spec["items"]:
			data_type = item["data_type"]
			if data_type == None:
				data_type = "bytes"
			new_spec["attributes"][spec_name]["items"][item["name"]] = {
				"value": item["value"],
				"original_name": item["original_name"],
				"data_type": data_type,
				"data_length": item["data_length"],
			}
	with open(filepath, "w") as f:
		json.dump(new_spec, f, indent="  ")

		

if __name__ == "__main__":
	update(sys.argv[1])	