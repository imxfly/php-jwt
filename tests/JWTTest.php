<?php

namespace X1nfly\JWT\Tests;

use X1nfly\JWT\JWT;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    public function testInvalidToken()
    {
        $payload = [
            "message" => "abc",
            "exp" => time() + 20
        ]; // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException(\Exception::class);
        $decoded = JWT::decode($encoded, 'my_key2');
    }

    public function testNullKeyFails()
    {
        $payload = [
            "message" => "abc",
            "exp" => time() + 20
        ]; // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException(\Exception::class);
        $decoded = JWT::decode($encoded, null);
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);
        $msg = JWT::encode('abc', $privKey, 'RS256');
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];
        $decoded = JWT::decode($msg, $pubKey);
        $this->assertEquals($decoded, 'abc');
    }

    public function testEmptyKeyFails()
    {
        $payload = [
            "message" => "abc",
            "exp" => time() + 20
        ]; // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException(\Exception::class);
        $decoded = JWT::decode($encoded, '');
    }

    public function testValidTokenWithNbf()
    {
        $payload = [
            "message" => "abc",
            "iat" => time(),
            "exp" => time() + 20, // time in the future
            "nbf" => time() - 20
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key');
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidToken()
    {
        $payload = [
            "message" => "abc",
            "exp" => time() + 20
        ]; // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key');
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testExpiredToken()
    {
        $this->expectException(\Exception::class);
        $payload = [
            "message" => "abc",
            "exp" => time() - 20
        ]; // time in the past
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key');
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException(\Exception::class);
        $payload = [
            "message" => "abc",
            "nbf" => time() + 20
        ]; // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key');
    }

    public function testEncodeDecode()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->assertEquals(JWT::decode($msg, 'my_key'), 'abc');
    }

    public function testUrlSafeCharacters()
    {
        $msg = JWT::encode('f?', 'a');
        $this->assertEquals('f?', JWT::decode($msg, 'a'));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException(\Exception::class);
        JWT::encode(pack('c', 128), 'a');
    }

    public function testBase64UrlEncode()
    {
        $this->assertEquals(JWT::base64UrlEncode("1234"), 'MTIzNA');
    }

    public function testBase64UrlDecode()
    {
        $this->assertEquals(JWT::base64UrlDecode("MTIzNA"), '1234');
    }
}
