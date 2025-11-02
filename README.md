# ctf-atlanta-cheatsheet
Reference repo for commands to progress in the labs

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
