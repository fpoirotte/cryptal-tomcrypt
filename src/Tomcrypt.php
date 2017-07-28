<?php

namespace fpoirotte\Cryptal\Plugins;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Tomcrypt implements CryptoInterface, PluginInterface
{
    protected $cipherConst;
    protected $modeConst;
    protected $tagLength;
    protected $padding;
    protected $cipher;
    private $key;

    protected static $supportedCiphers = null;
    protected static $supportedModes = null;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedCiphers["$cipher"], static::$supportedModes["$mode"])) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $this->cipherConst  = static::$supportedCiphers["$cipher"];
        $this->modeConst    = static::$supportedModes["$mode"];
        $this->tagLength    = $tagLength;
        $this->padding      = $padding;
        $this->cipher       = $cipher;
        $this->key          = $key;
    }

    protected static function checkSupport()
    {
        // First, build the list of supported ciphers.
        $candidates = array(
            (string) CipherEnum::CIPHER_3DES()      => 'TOMCRYPT_CIPHER_3DES',
            (string) CipherEnum::CIPHER_BLOWFISH()  => 'TOMCRYPT_CIPHER_BLOWFISH',
            (string) CipherEnum::CIPHER_CAST5()     => 'TOMCRYPT_CIPHER_CAST5',
            (string) CipherEnum::CIPHER_DES()       => 'TOMCRYPT_CIPHER_DES',
            (string) CipherEnum::CIPHER_RC2()       => 'TOMCRYPT_CIPHER_RC2',
            (string) CipherEnum::CIPHER_RC4()       => 'TOMCRYPT_CIPHER_RC4',
            (string) CipherEnum::CIPHER_SEED()      => 'TOMCRYPT_CIPHER_KSEED',
            (string) CipherEnum::CIPHER_TWOFISH()   => 'TOMCRYPT_CIPHER_TWOFISH',

            // Special notes on libtomcrypt's AES implementation.
            //
            // libtomcrypt uses the same cipher name for all variants of AES.
            // It then uses the key's length at runtime to determine
            // the actual variant in use.
            (string) CipherEnum::CIPHER_AES_128()   => 'TOMCRYPT_CIPHER_RIJNDAEL',
            (string) CipherEnum::CIPHER_AES_192()   => 'TOMCRYPT_CIPHER_RIJNDAEL',
            (string) CipherEnum::CIPHER_AES_256()   => 'TOMCRYPT_CIPHER_RIJNDAEL',
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
            (string) ModeEnum::MODE_CBC()   => 'TOMCRYPT_MODE_CBC',
            (string) ModeEnum::MODE_CCM()   => 'TOMCRYPT_MODE_CCM',
            (string) ModeEnum::MODE_CFB()   => 'TOMCRYPT_MODE_CFB',
            (string) ModeEnum::MODE_CTR()   => 'TOMCRYPT_MODE_CTR',
            (string) ModeEnum::MODE_EAX()   => 'TOMCRYPT_MODE_EAX',
            (string) ModeEnum::MODE_ECB()   => 'TOMCRYPT_MODE_ECB',
            (string) ModeEnum::MODE_GCM()   => 'TOMCRYPT_MODE_GCM',
            (string) ModeEnum::MODE_OCB()   => 'TOMCRYPT_MODE_OCB',
            (string) ModeEnum::MODE_OFB()   => 'TOMCRYPT_MODE_OFB',
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

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        // Depending on the mode, the IV is sometimes called nonce.
        $options    = array("authdata" => $aad, 'iv' => $iv, 'tag' => null, 'nonce' => $iv);
        $blockSize  = $this->getBlockSize();
        $missing    = $blockSize - (strlen($data) % $blockSize);
        $data      .= $this->padding->getPaddingData($blockSize, $missing);
        $res        = tomcrypt_cipher_encrypt($this->cipherConst, $this->key, $data, $this->modeConst, $options);
        $tag        = $options['tag'];
        return $res;
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {
        // Depending on the mode, the IV is sometimes called nonce.
        $options    = array("authdata" => $aad, 'iv' => $iv, 'nonce' => $iv, 'tag' => $tag);
        $blockSize  = $this->getBlockSize();
        $res        = tomcrypt_cipher_decrypt($this->cipherConst, $this->key, $data, $this->modeConst, $options);
        $padLen     = $this->padding->getPaddingSize($res, $blockSize);
        return $padLen ? (string) substr($res, 0, -$padLen) : $res;
    }

    public function getIVSize()
    {
        // LibTomCrypt's documentation says that the IV's size
        // should always match the cipher's block size.
        $res = tomcrypt_cipher_block_size($this->cipherConst);
        if (false === $res) {
           // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }

    public function getBlockSize()
    {
        $res = tomcrypt_cipher_block_size($this->cipherConst);
        if (false === $res) {
            // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        foreach (static::$supportedModes as $mode => $modeConst) {
            foreach (static::$supportedCiphers as $cipher => $cipherConst) {
                $registry->addCipher(
                    __CLASS__,
                    CipherEnum::$cipher(),
                    ModeEnum::$mode(),
                    ImplementationTypeEnum::TYPE_COMPILED()
                );
            }
        }
    }

    public function getCipher()
    {
        return $this->cipher;
    }

    public function getKey()
    {
        return $this->key;
    }
}
