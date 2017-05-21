<?php

namespace fpoirotte\Cryptal\Implementers;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\PaddingInterface;

class Crypto implements CryptoInterface
{
    protected $cipher;
    protected $mode;
    protected $tagLength;
    protected $padding;

    protected static $supportedCiphers = null;
    protected static $supportedModes = null;

    public function __construct($cipher, $mode, PaddingInterface $padding, $tagLength = 16)
    {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedCiphers[$cipher], static::$supportedModes[$mode])) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $this->cipher       = static::$supportedCiphers[$cipher];
        $this->mode         = static::$supportedModes[$mode];
        $this->tagLength    = $tagLength;
        $this->padding      = $padding;
    }

    protected static function checkSupport()
    {
        // First, build the list of supported ciphers.
        $candidates = array(
            CryptoInterface::CIPHER_3DES        => 'TOMCRYPT_CIPHER_3DES',
            CryptoInterface::CIPHER_BLOWFISH    => 'TOMCRYPT_CIPHER_BLOWFISH',
            CryptoInterface::CIPHER_CAST5       => 'TOMCRYPT_CIPHER_CAST5',
            CryptoInterface::CIPHER_DES         => 'TOMCRYPT_CIPHER_DES',
            CryptoInterface::CIPHER_RC2         => 'TOMCRYPT_CIPHER_RC2',
            CryptoInterface::CIPHER_RC4         => 'TOMCRYPT_CIPHER_RC4',
            CryptoInterface::CIPHER_SEED        => 'TOMCRYPT_CIPHER_KSEED',
            CryptoInterface::CIPHER_TWOFISH     => 'TOMCRYPT_CIPHER_TWOFISH',

            // Special notes on libtomcrypt's AES implementation.
            //
            // libtomcrypt uses the same cipher name for all variants of AES.
            // It then uses the key's length at runtime to determine
            // the actual variant in use.
            CryptoInterface::CIPHER_AES_128     => 'TOMCRYPT_CIPHER_RIJNDAEL',
            CryptoInterface::CIPHER_AES_192     => 'TOMCRYPT_CIPHER_RIJNDAEL',
            CryptoInterface::CIPHER_AES_256     => 'TOMCRYPT_CIPHER_RIJNDAEL',
        );

        $res = array();
        $supported = tomcrypt_list_ciphers();
        foreach ($candidates as $key => $value) {
            if (defined($value) && in_array(constant($value), $supported)) {
                $res[$key] = constant($value);
            }
        }
        static::$supportedCiphers = $res;

        // Now, build the list of supported modes.
        $candidates = array(
            CryptoInterface::MODE_CBC   => 'TOMCRYPT_MODE_CBC',
            CryptoInterface::MODE_CCM   => 'TOMCRYPT_MODE_CCM',
            CryptoInterface::MODE_CFB   => 'TOMCRYPT_MODE_CFB',
            CryptoInterface::MODE_CTR   => 'TOMCRYPT_MODE_CTR',
            CryptoInterface::MODE_EAX   => 'TOMCRYPT_MODE_EAX',
            CryptoInterface::MODE_ECB   => 'TOMCRYPT_MODE_ECB',
            CryptoInterface::MODE_GCM   => 'TOMCRYPT_MODE_GCM',
            CryptoInterface::MODE_OCB   => 'TOMCRYPT_MODE_OCB',
            CryptoInterface::MODE_OFB   => 'TOMCRYPT_MODE_OFB',
        );

        $res = array();
        $supported = tomcrypt_list_modes();
        foreach ($candidates as $key => $value) {
            if (defined($value) && in_array(constant($value), $supported)) {
                $res[$key] = constant($value);
            }
        }
        static::$supportedModes = $res;
    }

    public function encrypt($iv, $key, $data, &$tag = null, $aad = '')
    {
        // Depending on the mode, the IV is sometimes called nonce.
        $options    = array("authdata" => $aad, 'iv' => $iv, 'tag' => null, 'nonce' => $iv);
        $blockSize  = $this->getBlockSize();
        $missing    = $blockSize - (strlen($data) % $blockSize);
        $data      .= $this->padding->getPaddingData($blockSize, $missing);
        $res        = tomcrypt_cipher_encrypt($this->cipher, $key, $data, $this->mode, $options);
        $tag        = $options['tag'];
        return $res;
    }

    public function decrypt($iv, $key, $data, $tag = null, $aad = '')
    {
        // Depending on the mode, the IV is sometimes called nonce.
        $options    = array("authdata" => $aad, 'iv' => $iv, 'nonce' => $iv, 'tag' => $tag);
        $blockSize  = $this->getBlockSize();
        $res        = tomcrypt_cipher_decrypt($this->cipher, $key, $data, $this->mode, $options);
        $padLen     = $this->padding->getPaddingSize($res, $blockSize);
        return $padLen ? (string) substr($res, 0, -$padLen) : $res;
    }

    public function getIVSize()
    {
        // LibTomCrypt's documentation says that the IV's size
        // should always be the block size of the cipher.
        $res = tomcrypt_cipher_block_size($this->cipher);
        if (false === $res) {
           // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }

    public function getBlockSize()
    {
        $res = tomcrypt_cipher_block_size($this->cipher);
        if (false === $res) {
            // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }
}
