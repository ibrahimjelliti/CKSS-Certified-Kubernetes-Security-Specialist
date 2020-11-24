<p align="center">
  <img width="360" src="kubernetes-security-specialist-logo.png">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat">
  <img src="https://img.shields.io/badge/status-preview-brightgreen?style=flat">
  <img src="https://img.shields.io/github/issues-raw/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist?style=flat">
  
  <img src="https://img.shields.io/github/license/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist?style=flat">
  <img src="https://img.shields.io/github/stars/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist?style=social">
  <img src="https://img.shields.io/github/forks/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist?style=social">
</p>


# Certified Kubernetes Security Specialist - CKSS
This repository is a collection of resources to prepare for the Certified Kubernetes Security Specialist (CKSS) exam.
> The given references and links below are just assumptions and ideas around the [CKSS curriculum](https://github.com/cncf/curriculum/blob/master/CKS_Curriculum_%20v1.19.pdf).

## CKS Overview
The Kubernetes Security Specialist (CKS) certification ensure that the holder has the skills, knowledge, and competence on a broad range of best practices for securing container-based applications and Kubernetes platforms during build, deployment and runtime.

The certification is generally available to take from [here](https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist/) as anounced during the KubeCon NA20

## CKS Outline
The CKS test will be online, proctored and performance-based with 15-20 hands-on performance based tasks, and candidates have 2 hours to complete the exam tasks.

From the CKS Exam Curriculum repository, The exam will test domains and competencies including:
1. **Cluster Setup (10%)**: Best practice configuration to control the environment's access, rights and platform conformity.
2. **Cluster Hardening (15%)**: Protecting K8s API and utilize RBAC.
3. **System Hardening (15%)**: Improve the security of OS & Network; restrict access through IAM
4. **Minimize Microservice Vulnerabilities (20%)**: Utilizing on K8s various mechanisms to isolate, protect and control workload.
5. **Supply Chain Security (20%)**: Container oriented security, trusted resources, optimized container images, CVE scanning.
6. **Monitoring, Logging, and Runtime Security (20%)**: Analyse and detect threads.

# CKS Exam Preparation

In order to take the CKS exam, you must have **Valid CKA certification** prior to attempting the CKS exam to demonstrate you possess sufficient Kubernetes expertise.
A first good starting point for securing Kubernetes is the Task section [**Securing a Cluster**](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) of the official K8s documentation.
The exam will be based on **Kubernetes v1.19 documentation** as of November general availability announcement.

## Cluster Setup (10%)
<details><summary>Use Network security policies to restrict cluster level access</summary>
  
#### Allowed Ressources
* [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies)
* [Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)
* [Declare Network Policy](https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/)
* [Enforcing Network Policies in Kubernetes](https://kubernetes.io/blog/2017/10/enforcing-network-policies-in-kubernetes/)
#### 3rd Party Ressources
* [Get started with Kubernetes network policy](https://docs.projectcalico.org/security/kubernetes-network-policy)
* [kubernetes-network-policy-recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)
* [Kubernetes Network Policies Best Practices](https://blog.alcide.io/kubernetes-network-policies-best-practices)
* [Exploring Network Policies in Kubernetes](https://banzaicloud.com/blog/network-policy/)
</details>

<details><summary>Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)</summary>
  
#### 3rd Party Ressources
* [CIS benchmark for Kubernetes](https://www.cisecurity.org/benchmark/kubernetes/)
  * The benchmark is not yet available for `Kubernetes 1.19`, but it gives great understanding.
* [What is Center for Internet Security (CIS) Benchmarks](https://docs.microsoft.com/en-us/microsoft-365/compliance/offering-cis-benchmark)
* [Kube-bench](https://github.com/aquasecurity/kube-bench#running-kube-bench): A tool for running Kubernetes CIS Benchmark tests
* [GKE: CIS Benchmarks for etcd & kubelet](https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks#default-values) 
</summary>
</details>

<details><summary>Properly set up Ingress objects with security control</summary>

#### Allowed Ressources
* [Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/)
* [Ingress Controllers](https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/)
* [Set up Ingress on Minikube with the NGINX Ingress Controller](https://kubernetes.io/docs/tasks/access-application-cluster/ingress-minikube/)
* [secure an Ingress by specifying a Secret that contains a TLS private key and certificate](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls) 
* [How to deploy NGINX Ingress Controller](https://github.com/kubernetes/ingress-nginx/blob/master/docs/deploy/index.md)
* [TLS/HTTPS](https://github.com/kubernetes/ingress-nginx/blob/master/docs/user-guide/tls.md)
</details>

<details><summary>Protect node metadata and endpoints</summary>

#### Allowed Ressources
* [Restricting cloud metadata API access](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access)
* [Kubelet authentication/authorization](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-authentication-authorization/)
#### 3rd Party Ressources
* [Kubelet API](https://www.deepnetwork.com/blog/kubernetes/2020/01/13/kubelet-api.html)
* [Setting up secure endpoints in Kubernetes](https://blog.cloud66.com/setting-up-secure-endpoints-in-kubernetes/)
* [GKE Protecting cluster metadata](https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata)
* [Retrieving EC2 instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
* [EC2 Instance user data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
</details>

<details><summary>Minimize use of, and access to, GUI elements</summary>

#### Allowed Ressources
* [Web-based Kubernetes User Interface](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/)
* [Dashboard Access control](https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/README.md)
* [Dashboard Auth](https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/creating-sample-user.md)
#### 3rd Party Ressources
* [On Securing the Kubernetes Dashboard](https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca)
</details>

<details><summary>Verify platform binaries before deploying</summary>
  
#### Allowed Ressources
* [Kubernetes platform binaries](https://github.com/kubernetes/kubernetes/releases)
</details>

## Cluster Hardening (15%)
<details><summary>Restrict access to Kubernetes API</summary>

#### Allowed Ressources
* [Controlling Access to the Kubernetes API](https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/)
* [Certificate Signing Requests: Create Normal User](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user)
* [Generate cluster certificates (easyrsa, openssl or cfssl)](https://kubernetes.io/docs/concepts/cluster-administration/certificates/)
#### 3rd Party Ressources
* [GKE: Hardening your cluster's security](https://cloud.google.com/anthos/gke/docs/on-prem/how-to/hardening-your-cluster)
* [Kubernetes RBAC and TLS certificates – Kubernetes security guide](https://sysdig.com/blog/kubernetes-security-rbac-tls/)
* [Securing Your Kubernetes API Server](https://tufin.medium.com/protecting-your-kubernetes-api-server-5eefeea4cf8a)
</details>

<details><summary>Use Role Based Access Controls to minimize exposure</summary>

#### Allowed Ressources
* [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
* [Authorization modes for Kubernetes API server](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules)
#### 3rd Party Ressources
* [Site for Kubernetes RBAC](https://rbac.dev/)
* [Understand Role-Based Access Control in Kubernetes](https://www.youtube.com/watch?v=G3R24JSlGjY)
* [RBAC Study Guide](https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/Part-5-Security.md)
</details>

<details><summary>Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones</summary>
  
#### Allowed Ressources
* [Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
* [Default roles and role bindings](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings)
* [Authorization Modes](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules)
* [Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
* [Kubernetes should not mount default service account credentials by default](https://github.com/kubernetes/kubernetes/issues/57601)
#### 3rd Party Ressources
* [Kubernetes: Creating Service Accounts and Kubeconfigs](https://docs.armory.io/docs/armory-admin/manual-service-account/)
* [Kubernetes Access Control: Exploring Service Accounts](https://thenewstack.io/kubernetes-access-control-exploring-service-accounts/)
* [Disable default service account by deployments in Kubernetes](https://stackoverflow.com/questions/52583497/how-to-disable-the-use-of-a-default-service-account-by-a-statefulset-deployments)
* [Securing Kubernetes Clusters by Eliminating Risky Permissions](https://www.cyberark.com/resources/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions)
* [Understand Role Based Access Control in Kubernetes](https://www.youtube.com/watch?v=G3R24JSlGjY)
</details>

<details><summary>Update Cluster frequently</summary>
  
#### Allowed Ressources
* [Update Kubernetes frequently](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/)
</details>

## System Hardening (15%)
<details><summary>Minimize host OS footprint (reduce attack surface)</summary>

#### Allowed Ressources
* [Preventing containers from loading unwanted kernel modules](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#preventing-containers-from-loading-unwanted-kernel-modules)
#### 3rd Party Ressources
* [Reduce Kubernetes Attack Surfaces](https://blog.sonatype.com/kubesecops-kubernetes-security-practices-you-should-follow#:~:text=Reduce%20Kubernetes%20Attack%20Surfaces)
* [distribution independent linux](https://www.cisecurity.org/benchmark/distribution_independent_linux/)
* [CIS Benchmark Ubuntu Linux](https://www.cisecurity.org/benchmark/ubuntu_linux/)
* [CIS Benchmark RedHat](https://www.cisecurity.org/benchmark/red_hat_linux/)
* [CIS Benchmark Debian](https://www.cisecurity.org/benchmark/debian_linux/)
* [CIS Benchmark Centos](https://www.cisecurity.org/benchmark/centos_linux/)
* [CIS Benchmark SUSE](https://www.cisecurity.org/benchmark/suse_linux/)
* [CIS Benchmark Oracle](https://www.cisecurity.org/benchmark/oracle_linux/)
</details>

<details><summary>Minimize IAM roles</summary>

#### 3rd Party Ressources
* [What is the Principle of Least Privilege (POLP)?](https://digitalguardian.com/blog/what-principle-least-privilege-polp-best-practice-information-security-and-compliance)
* [IAM Grant least privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
</details>

<details><summary>Minimize external access to the network</summary>

#### Allowed Ressources
* [K8s quotas (services.loadbalancers)](https://kubernetes.io/docs/concepts/policy/resource-quotas/)
* [Restrict Access For LoadBalancer Service](https://v1-17.docs.kubernetes.io/docs/tasks/access-application-cluster/configure-cloud-provider-firewall/#restrict-access-for-loadbalancer-service)
* [Admission control plugin: ResourceQuota](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/resource-management/admission_control_resource_quota.md)
#### 3rd Party Ressources
* [Secure hosts with OS-level firewall (ufw)](https://help.replicated.com/community/t/managing-firewalls-with-ufw-on-kubernetes/230)
* [Configure firewall with ufw](https://www.linode.com/docs/security/firewalls/configure-firewall-with-ufw/)
* [Use security groups to secure network (Azure)](https://docs.microsoft.com/en-us/azure/aks/concepts-security#azure-network-security-groups)
* [Amazon EKS security group considerations](https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html)
* [Amazon EC2 security groups for Linux instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)
</details>

<details><summary>Appropriately use kernel hardening tools such as AppArmor, seccomp</summary>

#### Allowed Ressources
* [Restrict a Container's Access to Resources with AppArmor](https://kubernetes.io/docs/tutorials/clusters/apparmor/)
* [Restrict a Container's Syscalls with Seccomp](https://kubernetes.io/docs/tutorials/clusters/seccomp/)
#### 3rd Party Ressources
* [Kubernetes Hardening Best Practices](https://www.sumologic.com/kubernetes/security/#security-best-practices)
* [Container Security: Fundamental Technology Concepts that Protect Containerized Application by Liz Rice](https://cdn2.hubspot.net/hubfs/1665891/Assets/Container%20Security%20by%20Liz%20Rice%20-%20OReilly%20Apr%202020.pdf)
</details>

## Minimize Microservice Vulnerabilities (20%)
<details><summary>Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts</summary>

#### Allowed Ressources
* [Pod Security Policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)
* [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
* [OPA Gatekeeper: Policy and Governance for Kubernetes](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)
#### 3rd Party Ressources
* [Open Policy Agent Introduction](https://www.youtube.com/watch?v=Yup1FUc2Qn0)
* [Kubernetes security context, security policy, and network policy – Kubernetes security guide (part 2)](https://sysdig.com/blog/kubernetes-security-psp-network-policy/)
* [Enforce policies on Kubernetes objects with OPA](https://www.openpolicyagent.org/docs/v0.12.2/kubernetes-admission-control/)
* [Pod Security Policy](https://blog.alcide.io/pod-security-policy)
</details>

<details><summary>Manage kubernetes secrets</summary>

#### Allowed Ressources
* [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
* [Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
* [Using a KMS provider for data encryption](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/)
#### 3rd Party Ressources
* [katacoda lab around Secrets](https://www.katacoda.com/courses/kubernetes/managing-secrets)
* [Managing Secrets in Kubernetes](https://www.weave.works/blog/managing-secrets-in-kubernetes)
* [Secrets Store CSI driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver)
</details>

<details><summary>Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)</summary>

#### Allowed Ressources
* [container runtime](https://kubernetes.io/docs/concepts/containers/runtime-class/)
* [container runtime sandboxes examples](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/585-runtime-class/README.md#examples)
* [Enforce tenant isolation (Limit Ranges, Quotas, PSPs) with Policies](https://kubernetes.io/docs/concepts/policy/)
* [Affinity and anti-affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity)
#### 3rd Party Ressources
* [What is gVisor?](https://gvisor.dev/docs/)
* [Cluster multi-tenancy](https://cloud.google.com/kubernetes-engine/docs/concepts/multitenancy-overview)
* [Use gVisor to run Kubernetes pods](https://gvisor.dev/docs/user_guide/quick_start/kubernetes/)
* [Implementing secure Containers using Google’s gVisor](https://thenewstack.io/how-to-implement-secure-containers-using-googles-gvisor/)
* [Kata containers and Kubernetes: How they fit together?](https://platform9.com/blog/kata-containers-docker-and-kubernetes-how-they-all-fit-together/)
* [How to use Kata Containers with Kubernetes?](https://github.com/kata-containers/documentation/blob/master/how-to/how-to-use-k8s-with-cri-containerd-and-kata.md)
</details>

<details><summary>Implement pod to pod encryption by use of mTLS</summary>
  
#### Allowed Ressources
* [Manage TLS Certificates in a Cluster](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)
#### 3rd Party Ressources
* [Secure communication between services in Istio with mutual TLS](https://developer.ibm.com/technologies/containers/tutorials/istio-security-mtls/)
* [Mutual TLS Authentication (mTLS) De-Mystified](https://codeburst.io/mutual-tls-authentication-mtls-de-mystified-11fa2a52e9cf)
* [Traffic encryption using mTLS](https://www.istioworkshop.io/11-security/01-mtls/)
* [Using Istio to improve end-to-end security](https://istio.io/latest/blog/2017/0.1-auth/)
* [Linerd: automatic mtls](https://linkerd.io/2/features/automatic-mtls/)
</details>

## Supply Chain Security (20%)

<details><summary>Minimize base image footprint</summary>

#### 3rd Party Ressources
* [Why build small container images in Kubernetes](https://cloud.google.com/blog/products/gcp/kubernetes-best-practices-how-and-why-to-build-small-container-images)
* [Use the smallest base image possible](https://cloud.google.com/solutions/best-practices-for-building-containers#build-the-smallest-image-possible)
* [7 best practices for building containers](https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers)
* [distroless containers](https://github.com/GoogleContainerTools/distroless)
* [Docker multi-stage builds](https://docs.docker.com/develop/develop-images/multistage-build/)
* [Tips to Reduce Docker Image Sizes](https://hackernoon.com/tips-to-reduce-docker-image-sizes-876095da3b34)
* [3 simple tricks for smaller Docker images](https://learnk8s.io/blog/smaller-docker-images)
</details>

<details><summary>Secure your supply chain: whitelist allowed image registries, sign and validate images</summary>

#### Allowed Ressources
* [Using Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
* [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
* [A Guide to Kubernetes Admission Controllers](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/)
* [Ensure images only from approved sources are run](https://github.com/kubernetes/kubernetes/issues/22888)
#### 3rd Party Ressources
* [Content trust in Docker](https://docs.docker.com/engine/security/trust/content_trust/)
* [How to reject docker registries in Kubernetes?](https://stackoverflow.com/questions/54463125/how-to-reject-docker-registries-in-kubernetes)
* [Restrict pulling images from Registry](https://www.openpolicyagent.org/docs/latest/kubernetes-primer/)
* [Container image signatures in Kubernetes](https://medium.com/sse-blog/container-image-signatures-in-kubernetes-19264ac5d8ce)
</details>

<details><summary>Use static analysis of user workloads (e.g. kubernetes resources, docker files)</summary>

#### Allowed Ressources
* [11 Ways (Not) to Get Hacked: statically-analyse-yaml](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#7-statically-analyse-yaml)

#### 3rd Party Ressources
* [Static analysis with Clair](https://github.com/quay/clair)
* [Static analysis with Kube-score](https://kube-score.com/)
* [kubehunter](https://github.com/aquasecurity/kube-hunter)
* [kubesec](https://kubesec.io/)
* [Kubernetes static code analysis with Checkov](https://bridgecrew.io/blog/kubernetes-static-code-analysis-with-checkov/)
</details>

<details><summary>Scan images for known vulnerabilities</summary>
  
#### 3rd Party Ressources
* [CLAIR](https://github.com/quay/clair)
* [OpenSCAP](https://github.com/OpenSCAP/openscap)
* [Vuls](https://github.com/future-architect/vuls)
* [Scan your Docker images for vulnerabilities](https://medium.com/better-programming/scan-your-docker-images-for-vulnerabilities-81d37ae32cb3)
* [Scan your Docker containers for vulnerabilities with Clair](https://github.com/leahnp/clair-klar-kubernetes-demo)
</details>

## Monitoring, Logging and Runtime Security (20%)

<details><summary>Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities</summary>

#### Allowed Ressources
* [Restrict a Container's Syscalls with Seccomp](https://kubernetes.io/docs/tutorials/clusters/seccomp/)
* [Auditing with Falco (Obsoledted)](https://v1-16.docs.kubernetes.io/docs/tasks/debug-application-cluster/falco/)
#### 3rd Party Ressources
* [How to detect a Kubernetes vulnerability using Falco](https://sysdig.com/blog/how-to-detect-kubernetes-vulnerability-cve-2019-11246-using-falco/)
* [Kubernetes Security monitoring at scale](https://medium.com/@SkyscannerEng/kubernetes-security-monitoring-at-scale-with-sysdig-falco-a60cfdb0f67a)
</details>

<details><summary>Detect threats within physical infrastructure, apps, networks, data, users and workloads</summary>

#### 3rd Party Ressources
* [Common Kubernetes config security threats](https://www.cncf.io/blog/2020/08/07/common-kubernetes-config-security-threats/)
* [A guidance on Kubernetes threat modeling](https://www.trendmicro.com/vinfo/us/security/news/virtualization-and-cloud/guidance-on-kubernetes-threat-modeling)
* [Threat matrix for Kubernetes](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)
</details>

<details><summary>Detect all phases of attack regardless where it occurs and how it spreads</summary>

#### 3rd Party Ressources
* [Investigating Kubernetes attack scenarios in Threat Stack](https://www.threatstack.com/blog/kubernetes-attack-scenarios-part-1)
* [Anatomy of a Kubernetes attack – How untrusted Docker images fails us](https://www.optiv.com/explore-optiv-insights/source-zero/anatomy-kubernetes-attack-how-untrusted-docker-images-fail-us)
* [Investigating Kubernetes Attack Scenarios in Threat Stack (part 1)](https://www.threatstack.com/blog/kubernetes-attack-scenarios-part-1)
* [The seven phases of a cyber attack](https://www.dnvgl.com/article/the-seven-phases-of-a-cyber-attack-118270)
* [Threat matrix for Kubernetes](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)
* [MITRE ATT&CK framework for container runtime security with Falco](https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/)
* [Mitigating Kubernetes attacks](https://www.youtube.com/watch?v=HWv8ZKLCawM)
</details>

<details><summary>Perform deep analytical investigation and identification of bad actors within environment</summary>

#### 3rd Party Ressources
* [Kubernetes security 101: Risks and Best practices](https://www.stackrox.com/post/2020/05/kubernetes-security-101/)
</details>

<details><summary>Ensure immutability of containers at runtime</summary>

#### Allowed Ressources
* ["ReadOnlyRootFilesystem" (securityContext, PSP)](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems)
* ["readOnly" volume mount](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems)
* [Principles of Container-based Application Design](https://kubernetes.io/blog/2018/03/principles-of-container-app-design/)
#### 3rd Party Ressources
* [Leverage Kubernetes to ensure that containers are immutable](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/container_security_guide/keeping_containers_fresh_and_updateable#leveraging_kubernetes_and_openshift_to_ensure_that_containers_are_immutable)
* [Why I think we should all use immutable Docker images](https://medium.com/sroze/why-i-think-we-should-all-use-immutable-docker-images-9f4fdcb5212f)
* [With immutable infrastructure, your systems can rise from the dead](https://techbeacon.com/enterprise-it/immutable-infrastructure-your-systems-can-rise-dead)
</details>

<details><summary>Use Audit Logs to monitor access</summary>

#### Allowed Ressources
* [Kubernetes Audit](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)
#### 3rd Party Ressources
* [How to monitor Kubernetes audit logs?](https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/)
* [Kubernetes Audit logging](https://docs.sysdig.com/en/kubernetes-audit-logging.html)
* [Kubernetes Audit: Making Log Auditing a Viable Practice Again](https://blog.alcide.io/kubernetes-audit-making-log-auditing-a-viable-practice-again)
</details>

# Related Kubernetes security resources
* [Kubernetes Security Essentials (LFS260)](https://training.linuxfoundation.org/training/kubernetes-security-essentials-lfs260/) (The course will be available January 8, 2021)
* [Cloud Native Security Tutorial](https://tutorial.kubernetes-security.info/)
* [Killer Shell CKS Simulator](https://killer.sh/cks)
* [Sysdig Kubernetes Security Guide](https://sysdig.com/resources/ebooks/kubernetes-security-guide/)
* [Kubernetes Security Best Practices - Ian Lewis, Google](https://youtu.be/wqsUfvRyYpw)
* [Kubernetes security concepts and demos](https://youtu.be/VjlvS-qiz_U)
* [Tutorial: Getting Started With Cloud Native Security - Liz Rice, Aqua Security & Michael Hausenblas](https://youtu.be/MisS3wSds40)
* [11 Ways (Not) to Get Hacked](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/)
* [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)
* [Kubernetes CTF on vagrant environment](https://github.com/NodyHub/k8s-ctf-rocks)

# Keep Updating
* LIVING DOCUMENT - I WILL UPDATE IT FREQUENTLY WHEN I HAVE NEW INFORMATIONS
* PRs are always welcome so star, fork and contribute
  * please make a pull request if you would like to add or update 


Ibrahim Jelliti © 2020

