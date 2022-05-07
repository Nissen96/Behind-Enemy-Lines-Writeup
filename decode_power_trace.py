import numpy as np
from Crypto.PublicKey import RSA


def decode_power_trace(trace, offset=20, interval=50, threshold=180):
    bits = ""
    skip_next = False
    for i in range(offset, len(trace), interval):
        if skip_next:
            skip_next = False
            continue

        if trace[i] > threshold:
            if trace[i + interval] > threshold:
                bits += "1"
                skip_next = True
            else:
                bits += "0"

    return int(bits, 2)


def main():
    with open("trace.npy", "rb") as f:
        trace = np.load(f)
    d = decode_power_trace(trace)
    e = 0x10001
    n = 0xACC6F68FF45B36DB5A076379C470D70D0B19E73058158933AEB1D9CC1F370D267EE2F5F36C061C49FE02269FBA69E3C8783EFF9494F261638A604506260C076D280A94A691A373720958FD276AF60925D48C027419B12048A4BC329FB87DD7E2B34A0573B6042D7E65A54CC846A47E3BECD50C52ED3DE5BCA4C5609ED9AA4A65D8C13D342155F5EADA14110C57F1390E1A074A9FFBC157F6C39DADF2190DDBB40A16A7DD0BBB636A7EF1CF475170F7A0B8D2B4B481FB1C8B9A514D5C71FCFEB6138705A11B8D6C1C795C23179B3D7533BF295621A7275C07D021E24843FD160A734552B56A277452A1D0C41FD8443B8C5A7B46944447E934D268705BD3B137AF6E2EB36387EB3A68E0C8D8ACC431D2CDEE5E722CECBA1CE96EE05EBC1D80B8A4EAF05749F33EF52DD58CA52B1EEF2717B54729A04EACFF1975B409F56044990CB6E24C4D0B0FAC9E0192516D1EB70D8E9EE6CD03AD4C930F2E2E10FF206E52F3B4925602ED1CBACBDAA77FB9FB5B835D5ED9101444A1853007A2FDC084421B71ADAB5252639AA37B5B1A3EE99AF2BDECFC3C5D6917B1291D898CAF99CBA36D0D8E0AA833775AB062F2424CA5DA5250FAA84877308DA734884EC8725C557E2CFDD6272424CE7F25B05EE7FFBF82BAD4A656F355086D033DDD1E23C381E483242BE86B8A0F8F18D768F77941217A8821288EDCEDACA429A5F14A79A5B5F65B69D5
    key = RSA.construct((n, e, d))
    with open("rsakey.pem", "wb") as f:
        f.write(key.export_key("PEM"))


if __name__ == "__main__":
    main()
