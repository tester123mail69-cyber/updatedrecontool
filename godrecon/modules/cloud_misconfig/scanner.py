"""Enhanced cloud misconfiguration scanner."""

from __future__ import annotations

import asyncio
from typing import List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

_S3_URL = "https://{bucket}.s3.amazonaws.com"
_AZURE_URL = "https://{account}.blob.core.windows.net/{container}"
_GCP_URL = "https://storage.googleapis.com/{bucket}"
_FIREBASE_URL = "https://{project}.firebaseio.com/.json"
_K8S_URLS = [
    "https://{target}:443/api/v1",
    "http://{target}:8001/api/v1",
    "https://{target}:6443/api/v1",
    "http://{target}:10250/pods",
]
_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
]
_DOCKER_REGISTRY_URL = "https://{target}:5000/v2/_catalog"


class CloudMisconfigModule(BaseModule):
    """Scans for cloud misconfigurations across AWS, Azure, GCP, Firebase, K8s."""

    name = "cloud_misconfig"
    description = "Enhanced cloud misconfiguration scanner"
    version = "1.0.0"
    category = "cloud"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        findings: List[Finding] = []
        cfg = config.cloud_misconfig

        tasks = []
        if cfg.check_s3:
            tasks.append(self._check_s3(target))
        if cfg.check_azure:
            tasks.append(self._check_azure(target))
        if cfg.check_gcp:
            tasks.append(self._check_gcp(target))
        if cfg.check_firebase:
            tasks.append(self._check_firebase(target))
        if cfg.check_k8s:
            tasks.append(self._check_k8s(target))
        if cfg.check_metadata:
            tasks.append(self._check_metadata(target))
        tasks.append(self._check_docker_registry(target))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return ModuleResult(module_name=self.name, target=target, findings=findings)

    async def _check_s3(self, target: str) -> List[Finding]:
        findings = []
        domain_parts = target.replace("www.", "").split(".")
        bucket_names = [
            target,
            domain_parts[0],
            f"{domain_parts[0]}-backup",
            f"{domain_parts[0]}-assets",
            f"{domain_parts[0]}-static",
        ]
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for bucket in bucket_names[:3]:
                    url = _S3_URL.format(bucket=bucket)
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                            if resp.status in (200, 403):
                                findings.append(Finding(
                                    title=f"S3 Bucket Found: {bucket}",
                                    description=f"S3 bucket exists at {url} (HTTP {resp.status})",
                                    severity="high" if resp.status == 200 else "medium",
                                    tags=["cloud", "s3", "cloud_misconfig"],
                                    data={"url": url, "status": resp.status},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _check_azure(self, target: str) -> List[Finding]:
        findings = []
        name = target.split(".")[0]
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for container in ["public", "static", "$web"]:
                    url = _AZURE_URL.format(account=name, container=container)
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                            if resp.status in (200, 400, 403, 404):
                                if resp.status in (200, 400):
                                    findings.append(Finding(
                                        title=f"Azure Blob Container Found: {name}/{container}",
                                        description=f"Azure blob at {url} (HTTP {resp.status})",
                                        severity="high",
                                        tags=["cloud", "azure", "cloud_misconfig"],
                                        data={"url": url},
                                    ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _check_gcp(self, target: str) -> List[Finding]:
        findings = []
        name = target.replace(".", "-").split("-")[0]
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = _GCP_URL.format(bucket=name)
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                        if resp.status in (200, 403):
                            findings.append(Finding(
                                title=f"GCP Bucket Found: {name}",
                                description=f"GCP storage bucket at {url} (HTTP {resp.status})",
                                severity="high" if resp.status == 200 else "medium",
                                tags=["cloud", "gcp", "cloud_misconfig"],
                                data={"url": url},
                            ))
                except Exception:  # noqa: BLE001
                    pass
        except ImportError:
            pass
        return findings

    async def _check_firebase(self, target: str) -> List[Finding]:
        findings = []
        project = target.split(".")[0]
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = _FIREBASE_URL.format(project=project)
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            findings.append(Finding(
                                title=f"Firebase DB Open: {project}",
                                description=f"Firebase database at {url} is publicly readable",
                                severity="critical",
                                tags=["cloud", "firebase", "cloud_misconfig"],
                                data={"url": url},
                            ))
                except Exception:  # noqa: BLE001
                    pass
        except ImportError:
            pass
        return findings

    async def _check_k8s(self, target: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for url_tmpl in _K8S_URLS[:2]:
                    url = url_tmpl.format(target=target)
                    try:
                        async with session.get(
                            url, timeout=aiohttp.ClientTimeout(total=5),
                            ssl=False
                        ) as resp:
                            if resp.status == 200:
                                findings.append(Finding(
                                    title=f"Kubernetes API Exposed: {url}",
                                    description="Kubernetes API endpoint is publicly accessible",
                                    severity="critical",
                                    tags=["cloud", "kubernetes", "cloud_misconfig"],
                                    data={"url": url},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _check_metadata(self, target: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for url in _METADATA_URLS[:1]:
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                            if resp.status == 200:
                                findings.append(Finding(
                                    title="Cloud Metadata Endpoint Accessible",
                                    description=f"Instance metadata at {url} is reachable (SSRF risk)",
                                    severity="high",
                                    tags=["cloud", "metadata", "ssrf", "cloud_misconfig"],
                                    data={"url": url},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _check_docker_registry(self, target: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = _DOCKER_REGISTRY_URL.format(target=target)
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                        if resp.status == 200:
                            findings.append(Finding(
                                title=f"Docker Registry Exposed: {target}",
                                description=f"Docker registry catalog at {url} is publicly accessible",
                                severity="high",
                                tags=["cloud", "docker", "cloud_misconfig"],
                                data={"url": url},
                            ))
                except Exception:  # noqa: BLE001
                    pass
        except ImportError:
            pass
        return findings
