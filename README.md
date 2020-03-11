`$auth = Auth::login();
$this->accessToken = $auth->accessToken();
if ($this->accessToken && $auth->expiresIn() > 5) {
    return $this->accessToken;
}`

## Feel free to contribute & pr

__Following code most likely will fail to authenticate due to invalid captcha__
