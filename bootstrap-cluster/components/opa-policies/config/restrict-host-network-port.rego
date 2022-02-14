package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    input_share_hostnetwork(input.request.object)
    msg := sprintf("Using hostNetwork or hostPort is not allowed, pod: %v ", [input.request.object.metadata.name])
}

input_share_hostnetwork(o) {
    o.spec.hostNetwork
}

input_share_hostnetwork(o) {
    input_containers[_].ports[_].hostPort
}

input_containers[c] {
    c := input.request.object.spec.containers[_]
}

input_containers[c] {
    c := input.request.object.spec.initContainers[_]
}
