# PLCFuzz

This repository contains the public experimental code of PLCFuzz.

## Workflow

PLCFuzz should be used in two steps:

1. Collect protocol messages from the target device.
2. Run format inference to determine the protocol byte groups.
3. Put the target messages into the corresponding fuzz script.
4. Run fuzzing with the inferred protocol format.

## Step 1: Format Inference

Use `format_inference_runtime.py` to infer protocol format.

Before running it, the user should:

- Put the collected request messages into the script.
- Set the target device IP address.
- Set the target device port if needed.

The format inference step is used to determine which adjacent bytes share the same semantics.
These bytes will later be mutated as one group during fuzzing.

## Step 2: Fuzzing

After format inference, put the request messages into the `d_SEEDS` variable of the target fuzz script.

Available fuzz scripts:

- `schneider_fuzz.py`
- `delta_fuzz.py`
- `Mitsubishi_fuzz.py`
- `omron_fuzz.py`
- `siemens_fuzz.py`

Before running a fuzz script, the user should:

- Set `TARGET_PLC_IP`.
- Set the target port if the default one is not correct.
- Set `PAYLOAD_OFFSET`.
- Set `RESPONSE_OFFSET` if the script requires it.
- Put the collected messages into `d_SEEDS` if they are not already hardcoded.
- Set the output directories used for logs and results if necessary.

`PAYLOAD_OFFSET` should be defined by the user according to the format inference result.
It should point to the first byte after the function-code region.

For protocols that require response trimming before protocol-tree analysis, the user should also define `RESPONSE_OFFSET`.

## Output

Fuzzing results are written to:

- `logs/`
- `results/`

The exact files may differ slightly between device-specific fuzz scripts, but serialized fuzzing results and unexpected-response records are stored in these directories.

## Notes

- Format inference and fuzzing are separated on purpose.
- The user must first infer protocol format, then run fuzzing with the same message set.
- Device-specific differences are mainly in the packet-sending logic.
- The protocol-format inference method is shared across devices.
