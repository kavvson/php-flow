<?php
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Redis;

class Auth
{
    private $access_token;
    private $refresh_token;
    private $account_id;
    private $expires_in;

    const launcher_token = 'MzRhMDJjZjhmNDQxNGUyOWIxNTkyMTg3NmRhMzZmOWE6ZGFhZmJjY2M3Mzc3NDUwMzlkZmZlNTNkOTRmYzc2Y2Y=';
    const fortnite_token = 'ZWM2ODRiOGM2ODdmNDc5ZmFkZWEzY2IyYWQ4M2Y1YzY6ZTFmMzFjMjExZjI4NDEzMTg2MjYyZDM3YTEzZmM4NGQ=';

    const xsrf_TOKEN = 'https://www.epicgames.com/id/api/xsrf';
    const API_LOGIN = 'https://www.epicgames.com/id/api/login';
    const REPUTATION = 'https://www.epicgames.com/id/api/reputation';
    const Aredirect = 'https://www.epicgames.com/id/api/redirect';
    const API_EXCHANGE_CODE = 'https://www.epicgames.com/id/api/exchange';
    const API_TOKEN = 'https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token';

    private function __construct($access_token, $refresh_token, $account_id, $expires_in)
    {
        $this->access_token = $access_token;
        $this->refresh_token = $refresh_token;
        $this->account_id = $account_id;
        $this->expires_in = $expires_in;
    }

    /**
     * Will return the cached tokens or run the authenticator
     * @return Auth
     */
    public static function login()
    {

        if (Redis::get("aid")) {
            $data = json_decode(Redis::get("aid"));
            return new self($data->at, $data->rt, $data->aid, Redis::ttl("aid"));
        } else {
            $accounts = config('app.accounts');
            $account = array_keys($accounts);
            $password = array_values($accounts);

            $account = $account[1];
            $password = $password[1];
            self::launcher_authenticate($account, $password);
        }

    }


    /**
     *===============
     * Main Authentication flow
     *===============
     * @param $email
     * @param $password
     */
    public static function launcher_authenticate($email, $password)
    {
        #auth-flow-documentation 1a) Reputation
        $reputation = self::epicgames_reputation();

        #auth-flow-documentation 1b) Get XSRF
        $token = self::epicgames_get_xsrf();


        #auth-flow-documentation 2) Try to login
        $tryLogin = self::epicgames_login($email, $password, $token);

        /*
         * Can catch Conflict response ? and try the flow again ?
         * Most of the time it will be invalid_captcha
        */
        if ($tryLogin->getReasonPhrase() === "Conflict") {
            die('Unable to login '.$tryLogin->getBody()->getContents());
        }

        #auth-flow-documentation 5) Get Exchange code
        $code = self::epicgames_get_exchange_data($token);
        if (is_null($code)) {
            die('Unable to get exchange code');
        }

        #auth-flow-documentation 6) Get Tokens
        self::epicgames_get_token('d84ccecb8ffd4eb99ac1aa366485e83f', $token);

    }

    /**
     * #auth-flow-documentation 1a)
     *===============
     * Added on 2020-03-07
     *===============
     * @param $xsrf_token | Optional not sure if needed at all
     * @return null       | Not sure if I need look for a specific value here
     */
    public static function epicgames_reputation($xsrf_token = "")
    {
        $client = new Client(['headers' => ['x-xsrf-token' => $xsrf_token]]);
        $client->get(self::REPUTATION);
        return null;
    }

    /**
     * #auth-flow-documentation 1b)
     * ===============
     * Get the xsrf token from cookie
     *===============
     * @param string $cookieJar
     * @return array
     */
    public static function epicgames_get_xsrf($cookieJar = "")
    {
        $client = new Client(['cookies' => true]);
        $response = $client->get(self::xsrf_TOKEN);
        $cookieJar = $client->getConfig('cookies');
        foreach ($cookieJar->toArray() as $item) {
            if ($item['Name'] == "XSRF-TOKEN") {
                $token = $item['Value'];
            }
        }
        return ['jar' => $cookieJar, 'token' => $token];
    }


    /**
     * #auth-flow-documentation 2) Try to login with password and email
     * ===============
     * TODO :: Most of the cases ends up with Conflict invalid_captcha response
     * ===============
     * @param $email
     * @param $password
     * @param $token
     * @return \Psr\Http\Message\ResponseInterface
     */
    public static function epicgames_login($email, $password, $token)
    {
        $client = new Client(['http_errors' => false, 'cookies' => $token['jar']]);
        $response = $client->post(self::API_LOGIN,
            [
                'form_params' => [
                    'email' => $email,
                    'password' => $password,
                    'rememberMe' => 'true',
                    'captcha' => ''
                ],
                'headers' => [
                    'x-xsrf-token' => $token['token'],
                    'Content-Type' => 'application/x-www-form-urlencoded'
                ],

            ]);
        // According to docs redo this step fast
        $response = $client->post(self::API_LOGIN, [
            'form_params' => [
                'email' => $email,
                'password' => $password,
                'rememberMe' => 'true',
                'captcha' => ''
            ],
            'headers' => [
                'x-xsrf-token' => $token['token'],
                'Content-Type' => 'application/x-www-form-urlencoded'
            ],

        ]);
        return $response;
    }

    /**
     * #auth-flow-documentation 5)
     * ===============
     * Get exchange code
     * ===============
     * @param $xsrf_token
     * @return  string | null
     */
    public static function epicgames_get_exchange_data($xsrf_token)
    {
        $client = new Client(['headers' => ['x-xsrf-token' => $xsrf_token]]);
        $response = $client->get(self::API_EXCHANGE_CODE);
        return json_decode($response->getBody()->getContents())->code ?? null;
    }

    /**
     * #auth-flow-documentation 6)
     * ===============
     * As a short bypass - You can manually get the tokens from providing the
     * https://www.epicgames.com/id/api/exchange
     * {"code": XXXX }
     * Keep in mind tokens will expire after 8 hours
     *===============
     * @param $code
     * @param $cookie
     * @return Auth
     */
    public static function epicgames_get_token($code, $cookie)
    {
        $client = new Client(['http_errors' => false, 'cookies' => $cookie['jar']]);
        $response = $client->post(self::API_TOKEN,
            [
                'form_params' => [
                    'grant_type' => 'exchange_code',
                    'exchange_code' => $code,
                    "includePerms" => "true",
                    'token_type' => 'eg1'
                ],
                'headers' => [
                    'Authorization' => 'basic ' . self::fortnite_token
                ],

            ]);
        $data = json_decode($response->getBody()->getContents());

        /*
         * Store response in Redis cache
         */
        Redis::setex("aid", $data->expires_in, json_encode(
            [
                "at" => $data->access_token,
                "rt" => $data->refresh_token,
                "aid" => $data->account_id,
                "exp" => $data->expires_in
            ]
        ));
        return new self($data->access_token, $data->refresh_token, $data->account_id, $data->expires_in);
    }


    /**
     * @param $xsrf_token
     * @return string
     */
    public static function epicgames_redirect($xsrf_token)
    {
        $client = new Client(['headers' => ['x-xsrf-token' => $xsrf_token]]);
        $response = $client->get(self::Aredirect);
        return $response->getBody()->getContents();
    }

    public function refreshToken()
    {
        return $this->refresh_token;
    }

    public function expiresIn()
    {
        return $this->expires_in;
    }

    public function accessToken()
    {
        return $this->access_token;
    }
}