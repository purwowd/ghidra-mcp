# 19 - Container & Kubernetes Lab Protocol

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-09-06  
> **Depends On**: `14_RED_TEAM_KILLCHAIN.md`, `08_SAFETY_OVERRIDES.md`  
> **Template**: `templates/k8s_container_lab_template.py`

---

## Purpose

Standardize **container escape / K8s abuse** research in disposable clusters
(kind, k3d, minikube, Docker Desktop). Never against managed prod clusters.

---

## Preferred Lab Topologies

| Stack | Notes |
|-------|-------|
| **Docker single node** | Privileged pod / docker.sock mount demos |
| **kind / k3d** | Cheap multi-node API abuse |
| **minikube** | Simple SA token + RBAC misconfig labs |

Snapshot/rebuild after invasive tests.

---

## Technique Classes (Lab)

| Class | ATT&CK | Evidence |
|-------|--------|----------|
| docker.sock mount | T1611 | sock readable + API version |
| Privileged container | T1611 | CapEff / host mounts |
| SA token theft | T1552.007 | token path + API list pods |
| Escape via hostPath | T1611 | write marker on host path |
| RBAC overpermission | T1078 | create pod / exec proof |

Always use **marker files/secrets** (`LAB_K8S_MARKER=...`), never real cloud creds.

---

## Package Layout

```
pocs/K8S-<name>/
├── README.md
├── manifests/                 # vulnerable Deployment/RBAC
├── k8s_container_lab_template.py
├── attack/
│   └── notes.md
├── evidence/
└── detection/                 # audit log / Falco rules optional
```

Reproduce:

```bash
# inside lab pod/container
python k8s_container_lab_template.py --mode full --confirm-lab --enable-docker-sock-check
```

---

## Safety Gates

- `--confirm-lab` required for invasive checks
- No `kubectl` against unexplained kubecontexts — pin `KUBECONFIG` to lab file
- Cleanup: delete namespaces/pods created by the exercise

---

## Prompt Shape

```
Context: container/K8s lab (doc 19). Cluster: kind/k3d.
Misconfig: [docker.sock | privileged | weak SA].
Deliverable: manifests + enum/exploit script + marker evidence + cleanup.
Save under: pocs/K8S-<name>/
```
