import os
import json
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from .normalization import normalize_log as rule_based

_model = None
_tokenizer = None

def load_model():
    global _model, _tokenizer
    if _model is None:
        print("The local LLM is being loaded...")

        model_name = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
        _tokenizer = AutoTokenizer.from_pretrained(model_name)
        _model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype = torch.float32,
            device_map = "cpu",
            low_cpu_mem_usage = True,
        )
        print("The model is loaded.")
    return _model, _tokenizer 

def normalize_log_with_ai(source, raw_data):
    model, tokenizer = load_model()
    system_prompt = "You are a log normalization assistant. Your task is to convert the provided raw log into a standardized JSON object with the following fields: " \
    "- event_id: string or number identifying the event type" \
    "- user: username or user ID if present, else null" \
    "- ip: IP address if present, else null" \
    "- action: short description of the action (e.g., 'login', 'file access')"\
    "- status: success/failure or other status" \
    "- additional_fields: any other relevant information as a JSON object" \
    "Return ONLY the JSON object, no explanation" 
    user_prompt = f"Log source: {source}\nRaw log data: {json.dumps(raw_data)}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

    inputs = tokenizer(text, return_tensors="pt")
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=256,
            temperature=0.1,
            do_sample=True,
            top_p=0.9,
            pad_token_id=tokenizer.eos_token_id
        )

    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    try:
        
        import re
        json_match = re.search(r'(\{.*\})', response, re.DOTALL)
        if json_match:
            normalized = json.loads(json_match.group(1))
        else:
            normalized = rule_based(source, raw_data)
    except Exception as e:
        print(f"Local model error: {e}")
        normalized = rule_based(source, raw_data)

    return normalized