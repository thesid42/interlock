import json
import re
import hashlib
from pathlib import Path
import time

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, START, MessagesState, StateGraph


PROBE_PROTOCOL = "interlock-rca-probe-v1"
QWEN_PROBE_PROTOCOL = "interlock-qwen-capability-probe-v1"
RCA_PROTOCOL = "interlock-sandbox-rca-v2"
QWEN_TOOL_NAME = "interlock_qwen_complete"
CONSOLE_TOOL_NAME = "console_log"
MAX_INPUT_BYTES = 65536
MAX_COMPLETION_BYTES = 24000
GUILD_METADATA_HEADER = re.compile(
    r"\A\* This session was started at [^\r\n]{1,160}\r?\n"
    r"\* The current Guild workspace is named [^\r\n]{1,160}\r?\n"
    r"\* Guild frontend URL: https://app\.guild\.ai/?\r?\n\r?\n"
)


def parse_packet(state: MessagesState) -> dict:
    human = next(
        (message for message in reversed(state["messages"]) if isinstance(message, HumanMessage)),
        None,
    )
    if human is None or not isinstance(human.content, str):
        raise ValueError("Investigator input must be a JSON text message")
    if len(human.content.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("Investigator input exceeds the bounded packet limit")
    text = human.content
    metadata = GUILD_METADATA_HEADER.match(text)
    if metadata is not None:
        text = text[metadata.end():]
    packet = json.loads(text)
    if not isinstance(packet, dict):
        raise ValueError("Investigator input must be a JSON object")
    return packet


def probe(packet: dict) -> dict:
    if set(packet) != {"protocol", "input_nonce"}:
        raise ValueError("Probe accepts only its protocol and input nonce")
    nonce = packet["input_nonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", nonce):
        raise ValueError("Probe input nonce is invalid")
    return {
        "protocol_version": 2,
        "probe": True,
        "input_nonce": nonce,
        "python_execution": True,
    }


def redacted_probe_text(value: str) -> str:
    value = value[:4000]
    value = re.sub(r"(?i)(authorization|api[_-]?key|token|secret|password)[\s\"':=]+[^\s,}\"]+",
                   r"\1:[redacted]", value)
    value = re.sub(r"(?i)(bearer|basic)\s+[^\s,}\"]+", r"\1 [redacted]", value)
    return re.sub(r"[A-Za-z0-9_+/=-]{32,}", "[redacted-opaque]", value)


def schema_probe_value(value):
    if isinstance(value, type) and hasattr(value, "model_json_schema"):
        value = value.model_json_schema()
    if not isinstance(value, dict):
        return {"type": type(value).__name__}
    # Defaults and examples are not needed to establish the tool's input shape.
    def strip(node):
        if isinstance(node, dict):
            return {str(key): strip(item) for key, item in node.items()
                    if key not in {"default", "examples", "example"}}
        if isinstance(node, list):
            return [strip(item) for item in node[:64]]
        if isinstance(node, str):
            return node[:500]
        if node is None or isinstance(node, (int, float, bool)):
            return node
        return {"type": type(node).__name__}
    result = strip(value)
    return result if len(json.dumps(result).encode("utf-8")) <= 6000 else {"bounded": True}


async def qwen_capability_probe(packet: dict) -> dict:
    from guildai_langchain import guild_tools

    report = probe({"protocol": PROBE_PROTOCOL, "input_nonce": packet.get("input_nonce")})
    if set(packet) != {"protocol", "input_nonce"}:
        raise ValueError("Qwen probe accepts only its protocol and input nonce")
    tools = await guild_tools()
    matches = [tool for tool in tools if tool.name == QWEN_TOOL_NAME]
    if len(matches) != 1:
        raise RuntimeError("The required mediated Qwen tool is not configured")
    qwen = matches[0]
    report["qwen_probe"] = True
    report["tool"] = {"name": qwen.name, "type": type(qwen).__name__,
                      "module": type(qwen).__module__,
                      "attribute_names": sorted(str(key) for key in vars(qwen))[:64]}
    for name in ("args_schema", "args", "tool_call_schema", "input_schema"):
        try:
            report["tool"][name] = schema_probe_value(getattr(qwen, name, None))
        except Exception as error:
            report["tool"][name] = {"unavailable": type(error).__name__}
    request = {"model": "Qwen/Qwen3.8-27B", "stream": False, "max_tokens": 64,
               "messages": [{"role": "system", "content": "Return exactly one JSON object: {\"ok\":true}."},
                            {"role": "user", "content": "Public synthetic capability probe."}],
               "chat_template_kwargs": {"enable_thinking": False}}
    started = time.monotonic()
    try:
        value = await qwen.ainvoke(qwen_arguments(qwen, request))
        completion = completion_result(value, request, round((time.monotonic() - started) * 1000, 3))
        report["attempt"] = {"success": True, "model": completion["model"],
                             "content": completion["content"], "usage": completion["usage"]}
    except Exception as error:
        response = getattr(error, "response", None)
        detail = getattr(response, "text", None)
        if not isinstance(detail, str):
            detail = str(error)
        status = getattr(response, "status_code", None)
        report["attempt"] = {"success": False, "error_type": type(error).__name__,
                             "http_status": status if type(status) is int else None,
                             "detail": redacted_probe_text(detail)}
    report["model_calls_max"] = 1
    return report


def qwen_arguments(tool, request: dict) -> dict:
    schema = tool.args_schema
    if isinstance(schema, type) and hasattr(schema, "model_json_schema"):
        schema = schema.model_json_schema()
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError("Qwen operation must declare its actual object input schema")

    def accepts_body(body_schema):
        if not isinstance(body_schema, dict) or body_schema.get("type") != "object":
            return False
        properties = body_schema.get("properties")
        required = body_schema.get("required")
        return (isinstance(properties, dict) and isinstance(required, list)
                and all(isinstance(key, str) for key in required)
                and {"model", "messages"}.issubset(required)
                and {"model", "messages"}.issubset(properties)
                and set(request).issubset(properties)
                and set(required).issubset(request))

    if accepts_body(schema):
        return request
    properties = schema.get("properties")
    required = schema.get("required")
    if (isinstance(properties, dict) and isinstance(required, list)
            and all(isinstance(key, str) for key in required)):
        for field in ("input_body", "body"):
            if (field in required and set(required).issubset({field})
                    and accepts_body(properties.get(field))):
                return {field: request}
    raise ValueError("Qwen operation schema does not support the bounded completion request")


def final_json_content(content: str) -> str:
    value = content.strip()
    try:
        json.loads(value)
        return value
    except json.JSONDecodeError:
        pass
    if value.count("</think>") != 1:
        raise ValueError("Final content is not an exact JSON response")
    thinking, final = value.split("</think>", 1)
    if (len(thinking) > 16384 or thinking.lstrip().startswith(("{", "["))
            or thinking.count("<think>") > 1
            or ("<think>" in thinking and not thinking.startswith("<think>"))):
        raise ValueError("Invalid reasoning wrapper")
    final = final.strip()
    json.loads(final)
    return final


def unwrap_completion(value):
    for _ in range(4):
        if (isinstance(value, list) and len(value) == 1
                and isinstance(value[0], dict) and value[0].get("type") == "text"
                and isinstance(value[0].get("text"), str)):
            value = value[0]["text"]
        if isinstance(value, str):
            if len(value.encode("utf-8")) > MAX_COMPLETION_BYTES:
                raise ValueError("Qwen completion exceeds the bounded result limit")
            value = json.loads(value)
        if not isinstance(value, dict):
            raise ValueError("Qwen tool did not return a completion object")
        if len(json.dumps(value, ensure_ascii=True).encode("utf-8")) > MAX_COMPLETION_BYTES:
            raise ValueError("Qwen completion exceeds the bounded result limit")
        for field in ("status_code", "statusCode", "http_status", "status"):
            if field in value and (type(value[field]) is not int or value[field] != 200):
                raise ValueError("Qwen response envelope has an unsuccessful status")
        if value.get("isError") is not None and value.get("isError") is not False:
            raise ValueError("Qwen tool returned an error envelope")
        if "model" in value and "choices" in value:
            return value
        wrappers = [field for field in ("output_body", "body") if field in value]
        if len(wrappers) == 1:
            value = value[wrappers[0]]
            continue
        content = value.get("content")
        if (not wrappers and isinstance(content, list) and len(content) == 1
                and isinstance(content[0], dict) and content[0].get("type") == "text"
                and isinstance(content[0].get("text"), str)):
            value = content[0]["text"]
            continue
        raise ValueError("Qwen tool response envelope is unsupported")
    raise ValueError("Qwen response exceeds the bounded envelope depth")


def completion_result(value, request: dict, latency_ms: float) -> dict:
    value = unwrap_completion(value)
    if len(json.dumps(value, ensure_ascii=True).encode("utf-8")) > MAX_COMPLETION_BYTES:
        raise ValueError("Qwen completion exceeds the bounded result limit")
    if value.get("model") != request["model"]:
        raise ValueError("Qwen response model does not match the pinned request")
    choices = value.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise ValueError("Qwen must return exactly one completion choice")
    choice = choices[0]
    if choice.get("finish_reason") != "stop":
        raise ValueError("Qwen did not finish a complete response")
    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise ValueError("Qwen must return an assistant response")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip() or message.get("tool_calls"):
        raise ValueError("Qwen must return proposal text without tool calls")
    content = final_json_content(content)
    usage = value.get("usage")
    if usage is not None:
        if not isinstance(usage, dict):
            raise ValueError("Qwen usage metadata is invalid")
        bounded_usage = {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            number = usage.get(key)
            if number is not None:
                if type(number) is not int or not 0 <= number <= 1000000:
                    raise ValueError("Qwen token counts are invalid")
                bounded_usage[key] = number
        usage = bounded_usage
    return {"content": content, "model": value["model"], "usage": usage, "latency_ms": latency_ms}


def report_console(tools):
    candidates = [tool for tool in tools if tool.name == CONSOLE_TOOL_NAME]
    if len(candidates) != 1:
        raise RuntimeError("The required report console tool is not configured")
    return candidates[0], {"level": "info"}


async def emit_report(report: dict):
    from guildai_langchain import guild_tools

    console, arguments = report_console(await guild_tools())
    arguments["message"] = json.dumps(report, sort_keys=True, separators=(",", ":"))
    await console.ainvoke(arguments)


async def execute_rca(packet: dict) -> dict:
    import rca_contract
    from guildai_langchain import guild_tools

    rca_contract.validate_packet(packet)
    tools = await guild_tools()
    report_console(tools)
    candidates = [tool for tool in tools if tool.name == QWEN_TOOL_NAME]
    if len(candidates) != 1:
        raise RuntimeError("The required mediated Qwen tool is not configured")
    qwen = candidates[0]
    qwen_arguments(qwen, packet["checkpoint"]["request"])
    contract_sha256 = hashlib.sha256(Path(rca_contract.__file__).read_bytes()).hexdigest()

    async def complete(request: dict) -> dict:
        started = time.monotonic()
        try:
            value = await qwen.ainvoke(qwen_arguments(qwen, request))
        except Exception:
            raise RuntimeError("The approved Qwen completion failed") from None
        latency_ms = round((time.monotonic() - started) * 1000, 3)
        return completion_result(value, request, latency_ms)

    return await rca_contract.run_experiments(packet, complete, contract_sha256=contract_sha256)


async def investigate(state: MessagesState) -> dict:
    packet = parse_packet(state)
    if packet.get("protocol") == PROBE_PROTOCOL:
        report = probe(packet)
    elif packet.get("protocol") == QWEN_PROBE_PROTOCOL:
        report = await qwen_capability_probe(packet)
    elif packet.get("protocol") == RCA_PROTOCOL:
        report = await execute_rca(packet)
    else:
        raise ValueError("Unsupported investigator protocol")
    await emit_report(report)
    return {"messages": [AIMessage(content=json.dumps(report, sort_keys=True, separators=(",", ":")))]}


builder = StateGraph(MessagesState)
builder.add_node("investigate", investigate)
builder.add_edge(START, "investigate")
builder.add_edge("investigate", END)
graph = builder.compile()
