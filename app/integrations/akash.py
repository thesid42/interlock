"""Akash Console-hosted, OpenAI-compatible Qwen inference; no managed fallback."""

import json
from dataclasses import dataclass
from time import perf_counter
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from jsonschema import Draft202012Validator

from app.integrations.common import IntegrationError, IntegrationUnavailable, ProviderState


def normalize_base_url(value: str) -> str:
    """Accept only the base URL or known inference endpoint suffixes."""
    value = value.strip().rstrip("/")
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    path = parsed.path.rstrip("/")
    for suffix in ("/chat/completions", "/models"):
        if path.endswith("/v1" + suffix):
            path = path[:-len(suffix)]
            break
    if not path:
        path = "/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


def final_json_content(content: str) -> str:
    """Separate the one supported Qwen reasoning wrapper, not arbitrary prose."""
    value = content.strip()
    try:
        json.loads(value)
        return value
    except json.JSONDecodeError:
        pass
    if value.count("</think>") != 1:
        raise ValueError("Final content is not an exact JSON response")
    thinking, final = value.split("</think>", 1)
    if (len(thinking) > 16_384 or thinking.lstrip().startswith(("{", "["))
            or thinking.count("<think>") > 1
            or ("<think>" in thinking and not thinking.startswith("<think>"))):
        raise ValueError("Invalid reasoning wrapper")
    final = final.strip()
    json.loads(final)
    return final


@dataclass(frozen=True)
class CompletionResult:
    content: str
    model: str
    latency_ms: float
    usage: dict[str, Any] | None
    response_id: str | None


class AkashClient:
    def __init__(self, settings=None, *, api_key=None, base_url=None,
                 timeout: float | None = None, client: httpx.Client | None = None):
        self.provider = getattr(settings, "llm_provider", "akash_console")
        self.api_key = api_key if api_key is not None else getattr(settings, "llm_api_key", "")
        self.base_url = normalize_base_url(base_url or getattr(settings, "llm_base_url", ""))
        self.allow_unauthenticated = getattr(settings, "llm_allow_unauthenticated", False)
        self.http_public_only = getattr(settings, "llm_http_public_only", False)
        self.allowed_source_hosts = tuple(getattr(settings, "security_source_hosts", ()))
        self.timeout = timeout if timeout is not None else getattr(settings, "llm_timeout_seconds", 30.0)
        self.enable_thinking = getattr(settings, "llm_enable_thinking", False)
        self.send_thinking_parameter = getattr(settings, "llm_send_thinking_parameter", True)
        self.structured_outputs = getattr(settings, "llm_structured_outputs", False)
        self.agent_model = getattr(settings, "agent_model", "Qwen/Qwen3.8-27B")
        self._client = client
        self._owns_client = client is None
        self._discovered = False
        self._discovered_models: list[str] = []
        self._requested_model = ""
        self._served_model = ""
        self._verified = False
        self._detail = self._configuration_error() or self._status_detail("Configured; inference has not been verified")

    @property
    def public_data_only(self) -> bool:
        try:
            return urlsplit(self.base_url).scheme == "http"
        except ValueError:
            return False

    def _status_detail(self, message: str) -> str:
        if self.public_data_only:
            message = "HTTP public/synthetic-only development mode; " + message
        if not self.api_key and self.allow_unauthenticated:
            message += "; inference endpoint has no authentication"
        return message

    def _configuration_error(self) -> str | None:
        try:
            url = urlsplit(self.base_url)
            port = url.port
        except ValueError:
            return "LLM_BASE_URL is not a valid inference URL"
        if self.provider != "akash_console":
            return "LLM_PROVIDER must be akash_console for this deployment"
        if not self.api_key and not self.allow_unauthenticated:
            return "Missing LLM_API_KEY (inference service key, not Console management key)"
        if (url.scheme not in {"https", "http"} or not url.hostname or url.username or url.password
                or url.query or url.fragment or not url.path.endswith("/v1")
                or port == 0):
            return "LLM_BASE_URL must be a valid inference endpoint ending in /v1"
        if url.scheme == "http":
            if self.api_key:
                return "Inference credentials are never sent over HTTP; use an HTTPS endpoint"
            if not self.http_public_only:
                return "HTTP inference requires explicit LLM_HTTP_PUBLIC_ONLY development opt-in"
        return None

    def readiness(self) -> dict:
        state = ProviderState(self.provider, self._configuration_error() is None,
                              self._verified, self._detail).as_dict()
        return {**state, "models_discovered": self._discovered,
                "inference_verified": self._verified, "model": self.agent_model,
                "structured_outputs_enabled": self.structured_outputs,
                "transport": "http" if self.public_data_only else "https",
                "public_data_only": self.public_data_only,
                "authentication": "bearer" if self.api_key else "none",
                "discovered_models": list(self._discovered_models),
                "requested_model": self._requested_model or self.agent_model,
                "served_model": self._served_model,
                "model_identity_match": self._requested_model == self._served_model if self._served_model else None}

    def _request(self, method: str, path: str, **kwargs) -> dict:
        error = self._configuration_error()
        if error:
            raise IntegrationUnavailable(error)
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False)
        try:
            response = self._client.request(method, self.base_url + path,
                headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
                timeout=self.timeout, **kwargs)
            response.raise_for_status()
            if len(response.content) > 512_000:
                raise ValueError("Response exceeded bounded size")
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Expected JSON object")
        except httpx.HTTPStatusError as exc:
            self._verified = False
            self._detail = self._status_detail(f"Inference service returned HTTP {exc.response.status_code}")
            raise IntegrationError(self._detail) from None
        except (httpx.RequestError, ValueError) as exc:
            self._verified = False
            self._detail = self._status_detail(f"Inference request failed: {type(exc).__name__}")
            raise IntegrationError(self._detail) from None
        return data

    def discover_models(self) -> list[dict]:
        models = self._request("GET", "/models").get("data")
        if not isinstance(models, list) or len(models) > 1000 or any(
                not isinstance(item, dict) or not isinstance(item.get("id"), str) for item in models):
            raise IntegrationError("Inference service returned an invalid model catalog")
        self._discovered = True
        self._discovered_models = [item["id"] for item in models]
        if not self._verified:
            self._detail = self._status_detail("Model discovery verified; inference is not yet verified")
        return [{"id": item["id"], "object": item.get("object", "model")} for item in models]

    def completion(self, messages: list[dict], model: str, *, temperature: float | None = None,
                   max_tokens: int | None = None, response_schema: dict | None = None,
                   public_data: bool = False) -> CompletionResult:
        if self.public_data_only and not public_data:
            raise IntegrationUnavailable("HTTP development inference accepts only approved public/synthetic prompts; private and legacy memory prompts are blocked")
        if not model:
            raise IntegrationUnavailable("Configure the exact served AGENT_MODEL or JUDGE_MODEL alias")
        if not messages or len(messages) > 64 or len(json.dumps(messages)) > 131_072:
            raise IntegrationError("Inference input exceeds its bounded context")
        body = {"model": model, "messages": messages, "stream": False,
                "max_tokens": min(max_tokens or 2048, 4096)}
        if temperature is not None:
            body["temperature"] = temperature
        if self.send_thinking_parameter:
            body["chat_template_kwargs"] = {"enable_thinking": self.enable_thinking}
        if response_schema is not None and self.structured_outputs:
            body["response_format"] = {"type": "json_schema", "json_schema": {
                "name": "memguard_response", "strict": True, "schema": response_schema}}
        started = perf_counter()
        self._requested_model = model
        self._served_model = ""
        data = self._request("POST", "/chat/completions", json=body)
        try:
            choice = data["choices"][0]
            content = choice["message"]["content"]
            if not isinstance(content, str) or not content.strip() or len(content) > 49_152:
                raise ValueError("Missing or excessive final content")
            if choice.get("finish_reason") != "stop":
                raise ValueError("Incomplete final answer")
            result_model = data.get("model")
            usage = data.get("usage")
            if (not isinstance(result_model, str) or not result_model or len(result_model) > 300
                    or (usage is not None and not isinstance(usage, dict))):
                raise ValueError("Invalid model metadata")
            if response_schema is not None:
                content = final_json_content(content)
                Draft202012Validator(response_schema).validate(json.loads(content))
            if len(content) > 32_768:
                raise ValueError("Final content exceeds the bounded size")
        except Exception:
            self._verified = False
            self._detail = self._status_detail("Inference final content or schema validation failed")
            raise IntegrationError(self._detail) from None
        self._verified = True
        self._served_model = result_model
        self._detail = self._status_detail("Live inference verified; model reasoning is not authoritative evidence")
        if result_model != model:
            self._detail += "; response model identifier differs from requested alias"
        return CompletionResult(content, result_model, (perf_counter() - started) * 1000,
                                usage, data.get("id") if isinstance(data.get("id"), str) else None)

    def check_inference(self) -> dict:
        schema = {"type": "object", "properties": {"status": {"const": "ready"}},
                  "required": ["status"], "additionalProperties": False}
        result = self.completion([{"role": "user", "content": 'Return only {"status":"ready"}.'}],
                                 self.agent_model, temperature=0, max_tokens=256, response_schema=schema,
                                 public_data=True)
        return {**self.readiness(), "latency_ms": result.latency_ms, "model": result.model}

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
