package org.satochip.testsatochip.data

enum class AuthenticityStatus {
    Authentic,
    NotAuthentic,
    Unknown, // default when no card has been scanned yet
}