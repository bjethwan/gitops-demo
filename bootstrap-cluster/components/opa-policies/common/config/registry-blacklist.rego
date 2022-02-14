package kubernetes.admission

deprecated_registries = {
    "docker-registry.aeg.cloud/",
    "harbor.aeg.cloud/",
    "dfwdtrpr-awsw01.ds.dtvops.net/",
    "ov-dtr.awsw.cld.dtvops.net/",
    "dfwdtrlabawsw.ds.dtveng.net/"
}

deny[reason] {
  some container 
  input_request_containers[container]
  count({x | deprecated_registries[x]; startswith(container.image, x)}) > 0
  reason := sprintf("using some of the deprecated image registries: [%v]", [concat(", ", deprecated_registries)])
}

input_request_containers[container] {
  container := input.request.object.spec.containers[_]
}

input_request_containers[container] {
  container := input.request.object.spec.initContainers[_]
}

input_request_containers[container] {
  container := input.request.object.spec.template.spec.containers[_]
}

input_request_containers[container] {
  container := input.request.object.spec.template.spec.initContainers[_]
}
