// Fixtures generated offline with OpenSSL; nothing here is produced by the SDK, so
// the SDK is checked against an independent implementation.
//
//   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa8.pem
//   openssl rsa -in rsa8.pem -traditional -out rsa1.pem        # PKCS#1
//   openssl rsa -in rsa8.pem -pubout -out rsapub.pem
//   printf "activeledger legacy rsa fixture" > msg.txt
//   openssl dgst -sha256 -sign rsa8.pem msg.txt | base64 -w0   # RSA PKCS#1 v1.5, deterministic
//   openssl ecparam -name secp256k1 -genkey -noout -out ec.pem
//   openssl ec -in ec.pem -pubout -out ecpub.pem
//   openssl dgst -sha256 -sign ec.pem msg.txt | base64 -w0     # DER ECDSA
enum PEMFixtures {
    /// The message every fixture signature covers.
    static let message = "activeledger legacy rsa fixture"
    static let rsaPKCS8Private = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbpTtUsk4y++as
m5HP/kkTpK72CC7hj6b6NNBugJLXFIqc4J4ElNkecyQpV5VHyUPNabzxCPXbE79S
uUQpFQkSxoyRX/NtqFGQEoBCjUlCLw+/fH3tvnE44GYFcpgLpT/JR6yzqCWAKKQ/
NvLpPzKxL8nlZ5PrpwLBYiPA/HRp7f2x1cs4wQ6tjBQNGzGo1gdEvdP9o/q5jNAf
owj63nlCU+sRfl1pkWBLVdh4P1vyS6nz74z1FKUG3aRIFGpHfJi2GnqGgSRCCJLE
3kZsBuM/EclNA3tkqNdqAiS+6HltaPqDSdEzMTlXg4v1ME997Cu0XwOYndP9vhOA
StmoOfW7AgMBAAECggEABCnKSXyvfMuiIvHSV6bsm3rnNyuG3X+zLrQk8x+7Tcd9
4a5ca7Dzkc3wpK50DsSCbMcsR6I+uUpw7qyH9zVZ1ce70NOpNkCvVdQ43A7da8jI
eg3BbI+Qhb3y3KhxCraz2xVwuCmCP0hXBF3a54RKPdUSaHF50m7YMwYGAM5/6qlp
UuZlTEX7YkCJYVPvdxL4rIsl08SAb9BHb0kB6tW9ni8t6BtW32nwjrlRGRPz9t1u
FreykeFeMI7vH/IRv9m5HfbilUiS/ryzBJokuTfVwgf09uB8AK6gJMuYURyehzTS
WGNJGF9wAB+Jz19WlWjEkpw82GsbKCsrcI/XpAU66QKBgQDS6RbM1vu8kwFJTcl5
Lc7/KbsdCzU79hglYWT2DUvKGtW9m8g2QmrsBZLap4I3fdYxunE2l7L+ggx/5Z4X
nH83AmFzxGOMvCuWxW1uaOd0k4NPxSEU81ggUobbi79lrkgxk90IMMKefQae8WHV
Pn/9Et29MtqAQVA7Rofin1Xj1wKBgQC864sfSce1FNu/0IFbvymIZTj8U3+CZ6QX
mmY0P0G257R9TKPBZv68m/DfYeP7TK39+K9c/31jD62zqbL43i3ewQL8gtv7ODeP
4zt+Sy7E/yFjEMzN9Rfu0NawDTNaKT6kP/HAvEHdEldCKqFb6MW0WBOukioysSL8
Vee8fp1AvQKBgQCcOh4yc1ibMYU1aFJB2cXHyoCYnfG7zanLHp6rh+PI/CGxRpCC
aKZM2EAUiRnywtqDkWhFGQ90aJ6bqll1ge3VsITBPQrEd6oOD4Xkz/4Koy4US6Aa
pbp0jszoGVcYGYXOe4mxhHTU8yWRXJmsXJRvwKbRe7bQZBDrJ26GVqJHlwKBgGAj
odXXTwkIx1eSvPG6k2E02c4Wk9IB+hCE4zP9aOyydzg4czEtv76twON8xm8RM44G
Kv+xiNaLmQLP/iMFteQg5usnkNkEX8oagiEgE3nut8fZOdApxPckUcyfux1L1fPy
Eo3Zf88H0V37ocfK6il/lOyGt3C6kipFcTuMV2wlAoGAE18Okfl1jXiTX4ZDTXg/
jUrIwiDs3P2iJiCsFKug3mAf+NCFqhA+Vp5tCCSgZ5X6irDoYd/oCa1zbFiTG4WF
79MRD+4bZhUsL89Cv2ssVLO/uzvKqanMyq6h5407frLHwv8B3aCVW+1WGLO9hc29
w1afcaONYi+ROSyJ8+qnFB0=
-----END PRIVATE KEY-----
"""
    static let rsaPKCS1Private = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAm6U7VLJOMvvmrJuRz/5JE6Su9ggu4Y+m+jTQboCS1xSKnOCe
BJTZHnMkKVeVR8lDzWm88Qj12xO/UrlEKRUJEsaMkV/zbahRkBKAQo1JQi8Pv3x9
7b5xOOBmBXKYC6U/yUess6glgCikPzby6T8ysS/J5WeT66cCwWIjwPx0ae39sdXL
OMEOrYwUDRsxqNYHRL3T/aP6uYzQH6MI+t55QlPrEX5daZFgS1XYeD9b8kup8++M
9RSlBt2kSBRqR3yYthp6hoEkQgiSxN5GbAbjPxHJTQN7ZKjXagIkvuh5bWj6g0nR
MzE5V4OL9TBPfewrtF8DmJ3T/b4TgErZqDn1uwIDAQABAoIBAAQpykl8r3zLoiLx
0lem7Jt65zcrht1/sy60JPMfu03HfeGuXGuw85HN8KSudA7EgmzHLEeiPrlKcO6s
h/c1WdXHu9DTqTZAr1XUONwO3WvIyHoNwWyPkIW98tyocQq2s9sVcLgpgj9IVwRd
2ueESj3VEmhxedJu2DMGBgDOf+qpaVLmZUxF+2JAiWFT73cS+KyLJdPEgG/QR29J
AerVvZ4vLegbVt9p8I65URkT8/bdbha3spHhXjCO7x/yEb/ZuR324pVIkv68swSa
JLk31cIH9PbgfACuoCTLmFEcnoc00lhjSRhfcAAfic9fVpVoxJKcPNhrGygrK3CP
16QFOukCgYEA0ukWzNb7vJMBSU3JeS3O/ym7HQs1O/YYJWFk9g1LyhrVvZvINkJq
7AWS2qeCN33WMbpxNpey/oIMf+WeF5x/NwJhc8RjjLwrlsVtbmjndJODT8UhFPNY
IFKG24u/Za5IMZPdCDDCnn0GnvFh1T5//RLdvTLagEFQO0aH4p9V49cCgYEAvOuL
H0nHtRTbv9CBW78piGU4/FN/gmekF5pmND9Btue0fUyjwWb+vJvw32Hj+0yt/fiv
XP99Yw+ts6my+N4t3sEC/ILb+zg3j+M7fksuxP8hYxDMzfUX7tDWsA0zWik+pD/x
wLxB3RJXQiqhW+jFtFgTrpIqMrEi/FXnvH6dQL0CgYEAnDoeMnNYmzGFNWhSQdnF
x8qAmJ3xu82pyx6eq4fjyPwhsUaQgmimTNhAFIkZ8sLag5FoRRkPdGiem6pZdYHt
1bCEwT0KxHeqDg+F5M/+CqMuFEugGqW6dI7M6BlXGBmFznuJsYR01PMlkVyZrFyU
b8Cm0Xu20GQQ6yduhlaiR5cCgYBgI6HV108JCMdXkrzxupNhNNnOFpPSAfoQhOMz
/Wjssnc4OHMxLb++rcDjfMZvETOOBir/sYjWi5kCz/4jBbXkIObrJ5DZBF/KGoIh
IBN57rfH2TnQKcT3JFHMn7sdS9Xz8hKN2X/PB9Fd+6HHyuopf5TshrdwupIqRXE7
jFdsJQKBgBNfDpH5dY14k1+GQ014P41KyMIg7Nz9oiYgrBSroN5gH/jQhaoQPlae
bQgkoGeV+oqw6GHf6Amtc2xYkxuFhe/TEQ/uG2YVLC/PQr9rLFSzv7s7yqmpzMqu
oeeNO36yx8L/Ad2glVvtVhizvYXNvcNWn3GjjWIvkTksifPqpxQd
-----END RSA PRIVATE KEY-----
"""
    static let rsaPublic = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm6U7VLJOMvvmrJuRz/5J
E6Su9ggu4Y+m+jTQboCS1xSKnOCeBJTZHnMkKVeVR8lDzWm88Qj12xO/UrlEKRUJ
EsaMkV/zbahRkBKAQo1JQi8Pv3x97b5xOOBmBXKYC6U/yUess6glgCikPzby6T8y
sS/J5WeT66cCwWIjwPx0ae39sdXLOMEOrYwUDRsxqNYHRL3T/aP6uYzQH6MI+t55
QlPrEX5daZFgS1XYeD9b8kup8++M9RSlBt2kSBRqR3yYthp6hoEkQgiSxN5GbAbj
PxHJTQN7ZKjXagIkvuh5bWj6g0nRMzE5V4OL9TBPfewrtF8DmJ3T/b4TgErZqDn1
uwIDAQAB
-----END PUBLIC KEY-----
"""
    static let ecPrivate = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIEQhEpNTn3FREaaLfyP0QU8CHQr0sp/Q8UJYZ8q5vMi3oAcGBSuBBAAK
oUQDQgAEJ/n0TnymhgZVWeF6EAhFCoMIon1S6vjCMJ8SgGlAjqFqARACWX+RUxoZ
l6mgv4/UTmmtZC4AG5446AQJitc9xg==
-----END EC PRIVATE KEY-----
"""
    static let ecPublic = """
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEJ/n0TnymhgZVWeF6EAhFCoMIon1S6vjC
MJ8SgGlAjqFqARACWX+RUxoZl6mgv4/UTmmtZC4AG5446AQJitc9xg==
-----END PUBLIC KEY-----
"""
    static let rsaSignature = "ICk+Uw5Yr6xa6rLg1VMMCPhrZIlT3/ay9OH9n3QcxS1fP3cn6ef02T9lVWqEU+WYlcicHJMm/Rc5576dHbaKI2ZBR86iXZqnXLBioYj24JkcdVoM/ZhHutW2hlaDwJTO5FqaulJvnTsp/WeSLoWdQ+pZAuWqUUp5X8q4Lkigtr3JdRIRuuDXIvdfyl6jLR91gcH8tanGiGqv00mMs5bqLX5y4kTmT70bGKirv03rFop+uJmp+cFL5FEHEb1CoPCiIT+pHw9UjSMEXDrbJ3qKK3eoXsehCGMZt6ZvigCtxdMpuJ1j6P9siTQpNjbXMxzgwsdHZyOBlTzSWuGCVh0isA=="
    static let ecSignature = "MEUCIQCh/jrBpYgatBmcJVKU8BsaU3peygW0SmGSViUWFb4nCQIgbNb9P/YqsFEyy3zW9jiXUUHs/QGQ5TYBuG2eSWZY3NU="
    /// Uncompressed secp256k1 public key of `ecPrivate`, from `openssl ec -text`.
    static let ecPublicHex = "0x0427f9f44e7ca686065559e17a1008450a8308a27d52eaf8c2309f128069408ea16a011002597f91531a1997a9a0bf8fd44e69ad642e001b9e38e804098ad73dc6"
}
