rule Generic : generic secret{
    meta:
        description = "Detects generic secret - may produce false results"
        severity = "LOW"
        id = "LS0019"

    strings:
        $ = /(user|name)=\"([a-z0-9]+)\"\s(password)=\"([\w\W]+)\"/ nocase ascii
    condition:
        all of them
}
