rule detect_unauthorized_access {
    strings:
        $unauthorized_phrase = "Unauthorized access attempt"
    condition:
        $unauthorized_phrase
}
