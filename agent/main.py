import subprocess
import json
import time
from fastapi import FastAPI
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain.chains import LLMChain
import os
os.environ["LANGCHAIN_TRACING_V2"] = "true"

from langsmith import Client
client = Client()

app = FastAPI()

SHARED_DIR = "/shared"

class AnalyzeRequest(BaseModel):
    type: str
    input: str

def run(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.stdout, p.stderr, p.returncode

def trivy_scan(target_type, target):
    cmd = f"trivy image {target} --format json"
    out, err, code = run(cmd)
    if code != 0:
        raise Exception(err)
    return json.loads(out)

def extract_high(scan):
    vulns=[]
    for r in scan.get("Results",[]):
        for v in r.get("Vulnerabilities",[]):
            if v["Severity"] in ["HIGH","CRITICAL"]:
                vulns.append({
                    "id": v["VulnerabilityID"],
                    "severity": v["Severity"]
                })
    return vulns

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.1)

template = """
    You are a senior security remediation engineer.

    Original artifact:
    {original}

    High/Critical CVEs:
    {vulns}

    Return ONLY a safer compatible version string.

    Examples:
    alpine:3.20
    debian:11
    lodash@4.17.23
"""

prompt = PromptTemplate(
    input_variables=["original","vulns"],
    template=template
)

chain = LLMChain(llm=llm, prompt=prompt)

def ask_gpt(vulns, original):
    result = chain.invoke({
    "original": original,
    "vulns": json.dumps(vulns, indent=2)
    })

    return result["text"].strip()

@app.post("/analyze")
def analyze(req: AnalyzeRequest):

    start = time.time()

    before_scan = trivy_scan(req.type, req.input)
    before_vulns = extract_high(before_scan)

    new_version = ask_gpt(before_vulns, req.input)
    tokens = 0

    dockerfile = f"{SHARED_DIR}/Dockerfile.remediated"
    with open(dockerfile,"w") as f:
        f.write(f"FROM {new_version}\nRUN apk update || apt-get update\n")

    after_scan = trivy_scan(req.type, new_version)
    after_vulns = extract_high(after_scan)
    
    with open("/shared/rebuild.sh", "w") as f:
        f.write(f"docker build -t remediated-{new_version.replace(':','-')} .")

    # -------------------------------
    # Calculate removed CVEs
    # -------------------------------
    removed = set(v["id"] for v in before_vulns) - set(v["id"] for v in after_vulns)
    
    if len(before_vulns) == 0:
        reduction = 0
    else:
        reduction = round(((len(before_vulns)-len(after_vulns))/len(before_vulns))*100,2)



    report = f"{SHARED_DIR}/report.md"

    with open(report,"w") as f:
        f.write(f"""
                Before: {len(before_vulns)}
                After: {len(after_vulns)}

                Removed CVEs:
                {chr(10).join(removed)}

                Reduced by {reduction}%
                """)

    return {
        "original": req.input,
        "suggested": new_version,
        "before": len(before_vulns),
        "after": len(after_vulns),
        "tokens": tokens,
        "dockerfile": dockerfile,
        "report": report,
        "time": round(time.time()-start,2)
    }