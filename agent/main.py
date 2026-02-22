import subprocess
import json
import time
import os
import tempfile
import shutil
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
import requests

# ================================
# OpenTelemetry Setup
# ================================
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

resource = Resource(attributes={SERVICE_NAME: "ai-remediation-agent"})
trace.set_tracer_provider(TracerProvider(resource=resource))
tracer = trace.get_tracer(__name__)

processor = BatchSpanProcessor(
    OTLPSpanExporter(endpoint="http://otel-collector:4318/v1/traces")
)
trace.get_tracer_provider().add_span_processor(processor)

# ================================
# App Setup
# ================================
app = FastAPI()
SHARED_DIR = "/shared"
PYTHON_BIN = "python"  # or python3 inside container


class AnalyzeRequest(BaseModel):
    input: str  # Auto-detect type


# ================================
# Utilities
# ================================

def run(cmd: str):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.stdout, p.stderr, p.returncode


def detect_input(user_input: str) -> str:
    """
    Decide whether it's a container image, npm spec, or Python spec.
    """
    user_input = user_input.strip()

    # URLs
    if user_input.startswith("http"):
        if "npmjs.com" in user_input:
            return "npm"
        if "pypi.org" in user_input:
            return "pypi"

    # NPM: lodash@4.17.21
    if "@" in user_input and not user_input.startswith("@") and " " not in user_input:
        return "npm"

    # Python: django==4.2.11
    if "==" in user_input and " " not in user_input:
        return "pypi"

    # Fallback: container image
    return "image"


def parse_package(url: str):
    return url.rstrip("/").split("/")[-1]


# ================================
# Trivy Scanning
# ================================

def trivy_image(image: str):
    # remote registry mode, no docker.sock needed[web:22][web:25]
    cmd = f"trivy image --image-src remote {image} --format json"
    out, err, code = run(cmd)
    if code != 0:
        raise Exception(err)
    return json.loads(out)


def trivy_filesystem(path: str):
    cmd = f"trivy fs {path} --format json"
    out, err, code = run(cmd)
    if code != 0:
        raise Exception(err)
    return json.loads(out)


def extract_high(scan_json):
    vulns = []
    for result in scan_json.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            if v.get("Severity") in ["HIGH", "CRITICAL"]:
                vulns.append(
                    {
                        "id": v.get("VulnerabilityID"),
                        "severity": v.get("Severity"),
                        "cvss": v.get("CVSS", {}),
                    }
                )
    return vulns


# ================================
# Docker Hub validation (images)
# ================================

def validate_remote_image(image: str):
    """
    Validate that the given image:tag exists on Docker Hub.[web:17][web:26]
    """
    if ":" not in image:
        raise Exception(f"Generated image has no tag: {image}")
    repo, tag = image.split(":", 1)

    # e.g. ubuntu -> library/ubuntu[web:26]
    if "/" not in repo:
        repo_path = f"library/{repo}"
    else:
        repo_path = repo

    url = f"https://registry.hub.docker.com/v2/repositories/{repo_path}/tags/{tag}"
    try:
        r = requests.get(url, timeout=5)
    except Exception as e:
        raise Exception(f"Failed to validate image tag {image}: {e}")

    if r.status_code != 200:
        raise Exception(
            f"Generated tag does not exist on Docker Hub: {image} "
            f"(status {r.status_code})"
        )


SAFE_DEFAULTS = {
    "ubuntu": "ubuntu:22.04",
    "debian": "debian:12",
    "alpine": "alpine:3.20",
}


def fallback_image(original: str):
    base = original.split(":", 1)[0]
    return SAFE_DEFAULTS.get(base, original)


# ================================
# NPM handling (lodash@4.17.21)
# ================================

def trivy_npm_spec(spec: str):
    """
    Download an NPM package (with exact version) and scan via filesystem.[web:37][web:45]
    """
    workdir = tempfile.mkdtemp(prefix="npm-scan-")
    try:
        out, err, code = run(f"cd {workdir} && npm pack {spec}")
        if code != 0:
            raise Exception(f"npm pack failed for {spec}: {err}")
        return trivy_filesystem(workdir), workdir
    except Exception:
        shutil.rmtree(workdir, ignore_errors=True)
        raise


# ================================
# Python handling + pipdeptree
# ================================

def setup_pip_env(spec: str):
    """
    Create venv, install the requested package, return (workdir, venv_dir).[web:31][web:33]
    """
    workdir = tempfile.mkdtemp(prefix="py-scan-")
    venv_dir = os.path.join(workdir, "venv")

    out, err, code = run(f"{PYTHON_BIN} -m venv {venv_dir}")
    if code != 0:
        shutil.rmtree(workdir, ignore_errors=True)
        raise Exception(f"venv creation failed: {err}")

    pip_bin = os.path.join(venv_dir, "bin", "pip")
    out, err, code = run(f"{pip_bin} install {spec}")
    if code != 0:
        shutil.rmtree(workdir, ignore_errors=True)
        raise Exception(f"pip install failed for {spec}: {err}")

    return workdir, venv_dir


def get_pipdeptree(venv_dir: str):
    """
    Run pipdeptree in JSON-tree mode and return parsed structure.[web:36][web:40]
    """
    pip_bin = os.path.join(venv_dir, "bin", "pip")
    python_bin = os.path.join(venv_dir, "bin", "python")

    out, err, code = run(f"{pip_bin} install pipdeptree")
    if code != 0:
        raise Exception(f"pipdeptree install failed: {err}")

    cmd = f"{python_bin} -m pipdeptree --json-tree"
    out, err, code = run(cmd)
    if code != 0:
        raise Exception(f"pipdeptree failed: {err}")
    return json.loads(out)


# ================================
# LLM Setup
# ================================

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.1)

template = """
                You are a senior security remediation engineer.

                Original artifact:
                {original}

                High/Critical CVEs:
                {vulns}

                Dependency tree (may be empty for container images or npm packages):
                {deps}

                Return ONLY a safer compatible version string for the SAME image or package family.

                Strict rules:
                - For container images, use only tags that exist on Docker Hub.
                - Do NOT invent patch-level tags that are not official (e.g., ubuntu:22.04.3).
                - For packages, suggest a concrete version (e.g., lodash@4.17.21, django==4.2.11).
                - Output must be ONLY the image or package spec, with no extra text, no backticks, no explanation.

                Examples of valid outputs:
                alpine:3.20
                debian:12
                ubuntu:22.04
                lodash@4.17.10
                django==4.2.11
                """

prompt = PromptTemplate(
    input_variables=["original", "vulns", "deps"],
    template=template,
)


def ask_llm(original, vulns, deps=None):
    from langchain.callbacks import get_openai_callback

    deps_str = json.dumps(deps, indent=2) if deps is not None else "[]"

    with get_openai_callback() as cb:
        response = llm.invoke(
            prompt.format(
                original=original,
                vulns=json.dumps(vulns, indent=2),
                deps=deps_str,
            )
        )
        tokens = cb.total_tokens
        cost = cb.total_cost

    return response.content.strip(), tokens, cost


# ================================
# Main Endpoint
# ================================

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    with tracer.start_as_current_span("remediation_workflow") as span:
        start_time = time.time()

        workdir_to_cleanup = None

        try:
            mode = detect_input(req.input)
            deps = None

            # ---------------------------
            # BEFORE SCAN
            # ---------------------------
            if mode == "image":
                before_scan = trivy_image(req.input)

            elif mode == "npm":
                # e.g. lodash@4.17.10
                before_scan, workdir = trivy_npm_spec(req.input)
                workdir_to_cleanup = workdir

            elif mode == "pypi":
                # e.g. django==4.2.11
                workdir, venv_dir = setup_pip_env(req.input)
                workdir_to_cleanup = workdir
                deps = get_pipdeptree(venv_dir)
                before_scan = trivy_filesystem(workdir)

            else:
                raise Exception(f"Unknown mode: {mode}")

            before_vulns = extract_high(before_scan)

            # ---------------------------
            # LLM REMEDIATION
            # ---------------------------
            new_version, tokens, cost = ask_llm(req.input, before_vulns, deps)
            print(f"LLM suggested: {new_version}", flush=True)

            # For images, validate and maybe fallback
            if mode == "image":
                try:
                    validate_remote_image(new_version)
                except Exception as e:
                    print(f"Validation failed for {new_version}: {e}", flush=True)
                    new_version = fallback_image(req.input)
                    validate_remote_image(new_version)

            # ---------------------------
            # ARTIFACT GENERATION
            # ---------------------------
            if mode == "image":
                dockerfile_path = f"{SHARED_DIR}/Dockerfile.remediated"
                with open(dockerfile_path, "w") as f:
                    f.write(
                        f"FROM {new_version}\n"
                        "RUN apt-get update || apk update\n"
                    )

                rebuild_path = f"{SHARED_DIR}/rebuild.sh"
                with open(rebuild_path, "w") as f:
                    f.write(
                        f"docker build -t remediated-{new_version.replace(':','-')} ."
                    )

            else:
                # For npm/pypi, just store suggested version string
                pkg_file = f"{SHARED_DIR}/updated_package.txt"
                with open(pkg_file, "w") as f:
                    f.write(new_version)

            # ---------------------------
            # AFTER SCAN
            # ---------------------------
            if mode == "image":
                after_scan = trivy_image(new_version)
            elif mode == "npm":
                # rescan the NPM package if you want; for now reuse same workdir
                if workdir_to_cleanup is None:
                    raise Exception("Missing npm workdir for after-scan")
                after_scan = trivy_filesystem(workdir_to_cleanup)
            elif mode == "pypi":
                if workdir_to_cleanup is None:
                    raise Exception("Missing python workdir for after-scan")
                after_scan = trivy_filesystem(workdir_to_cleanup)

            after_vulns = extract_high(after_scan)

            # ---------------------------
            # CVE COMPARISON
            # ---------------------------
            before_ids = set(v["id"] for v in before_vulns)
            after_ids = set(v["id"] for v in after_vulns)

            removed = before_ids - after_ids

            reduction = 0
            if len(before_vulns) > 0:
                reduction = round(
                    ((len(before_vulns) - len(after_vulns)) / len(before_vulns)) * 100,
                    2,
                )

            # ---------------------------
            # REPORT
            # ---------------------------
            report_path = f"{SHARED_DIR}/report.md"
            with open(report_path, "w") as f:
                f.write(
                    f"""
                    # Vulnerability Report

                    ## Before
                    Total HIGH/CRITICAL: {len(before_vulns)}

                    ## After
                    Total HIGH/CRITICAL: {len(after_vulns)}

                    ## Removed CVEs
                    {chr(10).join(removed)}

                    ## Summary
                    Reduced critical vulnerabilities by {reduction}%
                    """
                )

            execution_time = round(time.time() - start_time, 2)

            # ---------------------------
            # Observability Attributes
            # ---------------------------
            span.set_attribute("before_vulns", len(before_vulns))
            span.set_attribute("after_vulns", len(after_vulns))
            span.set_attribute("reduction_percent", reduction)
            span.set_attribute("execution_time", execution_time)
            span.set_attribute("llm_tokens", tokens)
            span.set_attribute("llm_cost_estimate", cost)

            return {
                "original": req.input,
                "mode": mode,
                "suggested": new_version,
                "before": len(before_vulns),
                "after": len(after_vulns),
                "removed_cves": list(removed),
                "reduction_percent": reduction,
                "tokens": tokens,
                "estimated_cost": cost,
                "execution_time": execution_time,
                "report": report_path,
                "dependency_tree": deps,
            }

        except Exception as e:
            span.set_attribute("error", str(e))
            raise HTTPException(status_code=500, detail=str(e))

        finally:
            if workdir_to_cleanup and os.path.isdir(workdir_to_cleanup):
                shutil.rmtree(workdir_to_cleanup, ignore_errors=True)
