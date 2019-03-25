<?php
namespace X1nfly\JWT;

use \Exception;

class JWT
{
    /**
     * The algorithms that this package supports.
     */
    public static $algs = [
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
    ];

    /**
     * Converts and signs the data into a JWT string.
     *
     * @param object|array $payload The payload
     * @param string $key The secret key, if the algorithm is Public-key cryptography,
     *              use the private key
     * @param string $alg The algorithm
     * @param array $header The optional header parameters
     *
     * @return string The JWT string
     *
     * @throws Exception
     */
    public static function encode($payload, $key, $alg = 'HS256', $header = []) :string
    {
        $headers = ['typ' => 'JWT', 'alg' => $alg];
        if (!empty($header)) {
            $headers = array_merge($headers, $header);
        }

        $headersJSON = json_encode($headers);
        if (!$headersJSON) {
            throw new Exception('The part of header JSON encode failed.');
        }

        $payloadJSON = json_encode($payload);
        if (!$payloadJSON) {
            throw new Exception('The part of payload JSON encode failed');
        }

        $segs = [];
        $segs[] = static::base64UrlEncode(json_encode($headers));
        $segs[] = static::base64UrlEncode(json_encode($payload));
        $segs[] = static::base64UrlEncode(static::sign(implode('.', $segs), $key, $alg));

        return implode('.', $segs);
    }

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string        $jwt            The JWT
     * @param string|array  $key            The key, or map of keys.
     *                                      If the algorithm used is asymmetric, this is the public key
     *
     * @return object The JWT's payload as a PHP object
     */
    public static function decode($jwt, $key)
    {
        $segs = explode('.', $jwt);
        if (count($segs) !== 3) {
            throw new Exception("Invalid JWT.", 1);
        }
        $header = json_decode(static::base64UrlDecode($segs[0]), false, 512, JSON_BIGINT_AS_STRING);
        if ($header === null) {
            throw new Exception("Empty header.", 1);
        }
        if (!isset($header->alg) || !array_key_exists($header->alg, static::$algs)) {
            throw new Exception("Unsupported algorithm.", 1);
        }
        if (is_array($key)) {
            if (!isset($header->kid) || !array_key_exists($header->kid, $key)) {
                throw new Exception('"kid" invalid, unable to lookup correct key', 1);
            }
        }
        if (false === ($sig = static::base64UrlDecode($segs[2]))) {
            throw new UnexpectedValueException('Invalid signature encoding');
        }

        if (!static::verify($segs[0].'.'.$segs[1], $sig, $key, $header->alg)) {
            throw new Exception("Signature verification failed", 1);
        }

        $payload = json_decode(static::base64UrlDecode($segs[1]), false, 512, JSON_BIGINT_AS_STRING);
        if (isset($payload->nbf) && $payload->nbf > time()) {
            throw new Exception("This JWT is not valid before " . date('Y-m-d H:i:s', $payload->nbf), 1);
        }
        if (isset($payload->exp) && time() >= $payload->exp) {
            throw new Exception("This JWT is expired.", 1);
        }

        return $payload;
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string            $data        The original message (header and body)
     * @param string            $signature  The original signature
     * @param string|resource   $key        For HS*, a string key works. for RS*, must be a resource of an openssl public key
     * @param string            $alg        The algorithm
     *
     * @return bool
     *
     * @throws Exception
     */
    public static function verify($data, $signature, $key, $alg)
    {
        if (!array_key_exists($alg, static::$algs)) {
            throw new Exception("The algorithm is not supported.", 1);
        }

        list($func, $algorithm) = static::$algs[$alg];
        if ($func === 'hash_hmac') {
            return hash_equals(hash_hmac($algorithm, $data, $key, false), $signature);
        }
        if ($func === 'openssl') {
            $success = openssl_verify($data, $signature, $key, $algorithm);
            if ($success === 1) {
                return true;
            } elseif ($success === 0) {
                return false;
            }
            // Returns 1 if the signature is correct, 0 if it is incorrect, and -1 on error.
            throw new DomainException('OpenSSL error: ' . openssl_error_string());
        }

        return false;
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string            $msg    The message to sign
     * @param string|resource   $key    The secret key
     * @param string            $alg    The signing algorithm.
     *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     *
     * @return string An encrypted message
     *
     * @throws Exception
     */
    protected static function sign($data, $key, $alg) :string
    {
        if (!array_key_exists($alg, static::$algs)) {
            throw new Exception("The algorithm is not supported.", 1);
        }

        list($func, $algorithm) = static::$algs[$alg];
        if ($func === 'hash_hmac') {
            return hash_hmac($algorithm, $data, $key, false);
        }
        $signature = '';
        $success = openssl_sign($data, $signature, $key, $algorithm);
        if (!$success) {
            throw new Exception("OpenSSL unable to sign data");
        } else {
            return $signature;
        }
    }

    /**
     * Encode a string with the URL-safe base64.
     *
     * @param string $data The string you want to encode
     *
     * @return string The URL-safe base64 encode you passed in
     */
    public static function base64UrlEncode(string $data) :string
    {
        return str_replace('=', '', strtr(base64_encode($data), "+/", "-_"));
    }

    /**
     * Decode a string with the URL-safe base64.
     *
     * @param string $data The base64 encode
     *
     * @return string The URL-safe base64 decoded string
     */
    public static function base64UrlDecode(string $data) :string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }
}
