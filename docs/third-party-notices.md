# Third-party notices

The `lt` release bundle redistributes these components:

- **llama.cpp** at revision `c1d0e7a004015f23bc0233470b747b596f29b264`, under the MIT License. Its complete license is shipped in `THIRD_PARTY_LICENSES/llama.cpp-MIT.txt` in every native bundle.
- **SmolLM2-135M-Instruct Q4_K_M**, an Apache-2.0 quantization of [HuggingFaceTB/SmolLM2-135M](https://huggingface.co/HuggingFaceTB/SmolLM2-135M). The source model card and license are available at that URL; the exact GGUF file and SHA-256 are pinned in `scripts/build-release-bundle.sh`.

`lt` does not redistribute source code from Vercel fx. Its compact CLI shape is an independent implementation informed by a review of fx at commit `fff3f63e348dec846bb235332974226bd2feae26`.
