---
title: "acorn dev render"
---
## acorn dev render

Evaluate and display an acorn.cue with deploy params

```
acorn dev render [flags] DIRECTORY
```

### Options

```
  -h, --help   help for render
```

### Options inherited from parent commands

```
  -A, --all-namespaces       Namespace to work in
  -b, --bidirectional-sync   Download changes in addition to uploading
      --context string       Context to use in the kubeconfig file
      --dangerous            Automatically approve all privileges requested by the application
  -d, --dns strings          Assign a friendly domain to a published container (format public:private) (ex: example.com:web)
  -f, --file string          Name of the dev file (default "DIRECTORY/acorn.cue")
      --kubeconfig string    Location of a kubeconfig file
  -l, --link strings         Link external app as a service in the current app (format app-name:service-name)
  -n, --name string          Name of app to create
      --namespace string     Namespace to work in (default "acorn")
      --profile strings      Profile to assign default values
  -p, --publish strings      Publish exposed port of application (format [public:]private) (ex 81:80)
  -P, --publish-all          Publish all exposed ports of application
  -s, --secret strings       Bind an existing secret (format existing:sec-name) (ex: sec-name:app-secret)
  -v, --volume strings       Bind an existing volume (format existing:vol-name) (ex: pvc-name:app-data)
```

### SEE ALSO

* [acorn dev](acorn_dev.md)	 - Build and run an app in development mode

