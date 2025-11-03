# CTF Atlanta Cheatsheet
Reference repository for commands to progress in the CTF labs

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
