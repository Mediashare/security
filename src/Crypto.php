<?php

namespace Kzu\Security;

use phpseclib3\Crypt\AES;

Trait Crypto {
    static public $secret;

    static public function encrypt(string $data, ?string $secret = null, ?string $vector = null) {
        $cipher = new AES('ctr');
        $secret = hash('sha256', $secret ?? Crypto::$secret);
        $cipher->setIV($vector ?? substr(hash('sha256', $secret), 0, 16));
        $cipher->setPassword($secret);
        
        return base64_encode($cipher->encrypt($data)) ?? false;
    }

    static public function decrypt(string $data , ?string $secret = null, ?string $vector = null) {
        $cipher = new AES('ctr');
        $secret = hash('sha256', $secret ?? Crypto::$secret);
        $cipher->setIV($vector ?? substr(hash('sha256', $secret), 0, 16));
        $cipher->setPassword($secret);

        return $cipher->decrypt(base64_decode($data)) ?? false; 
    }
}