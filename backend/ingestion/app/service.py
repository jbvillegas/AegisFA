import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

_model = None
_tokenizer = None

def load_model():
    global _model, _tokenizer
    if _model is None:
        print("The local LLM is being loaded...")

        model_name = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
        _tokenizer = AutoTokenizer.from_pretrained(model_name)
        try:
            _model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="auto",
                low_cpu_mem_usage=True,
            )
        except Exception as e:
            raise RuntimeError(
                "Local LLM loading failed. Install 'accelerate' and ensure"
                " enough memory for model loading. Original error: "
                f"{e}"
            )
        print("The model is loaded.")
    return _model, _tokenizer
