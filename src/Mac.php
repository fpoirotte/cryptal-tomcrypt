<?php

namespace fpoirotte\Cryptal\Plugins\Tomcrypt;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\AbstractMac;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\MacEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;
use fpoirotte\Cryptal\SubAlgorithmAbstractEnum;

class Mac extends AbstractMac implements PluginInterface
{
    private $data;
    private $key;
    private $nonce;
    protected $algo;
    protected $innerAlgo;
    protected static $supportedAlgos = null;

    public function __construct(
        MacEnum $macAlgorithm,
        SubAlgorithmAbstractEnum $innerAlgorithm,
        $key,
        $nonce = ''
    ) {
        if (static::$supportedAlgos === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedAlgos['mac']["$macAlgorithm"])) {
            throw new \InvalidArgumentException('Unsupported MAC algorithm');
        }
        $this->algo = static::$supportedAlgos['mac']["$macAlgorithm"];

        if ($innerAlgorithm instanceof CipherEnum) {
            if (!isset(static::$supportedAlgos['crypto']["$innerAlgorithm"])) {
                throw new \InvalidArgumentException('Unsupported cipher algorithm');
            }
            $this->innerAlgo    = static::$supportedAlgos['crypto']["$innerAlgorithm"];
        } elseif ($innerAlgorithm instanceof HashEnum) {
            if (!isset(static::$supportedAlgos['hash']["$innerAlgorithm"])) {
                throw new \InvalidArgumentException('Unsupported hashing algorithm');
            }
            $this->innerAlgo    = static::$supportedAlgos['hash']["$innerAlgorithm"];
        } else {
            throw new \InvalidArgumentException('Unsupported inner algorithm');
        }

        $this->key          = $key;
        $this->nonce        = $nonce;
    }

    protected static function checkSupport()
    {
        static::$supportedAlgos = array();

        // Supported hash algorithms
        $hashes  = array(
            (string) HashEnum::HASH_MD2()       => 'TOMCRYPT_HASH_MD2',
            (string) HashEnum::HASH_MD4()       => 'TOMCRYPT_HASH_MD4',
            (string) HashEnum::HASH_MD5()       => 'TOMCRYPT_HASH_MD5',
            (string) HashEnum::HASH_RIPEMD160() => 'TOMCRYPT_HASH_RIPEMD160',
            (string) HashEnum::HASH_SHA1()      => 'TOMCRYPT_HASH_SHA1',
            (string) HashEnum::HASH_SHA2_224()  => 'TOMCRYPT_HASH_SHA2_224',
            (string) HashEnum::HASH_SHA2_256()  => 'TOMCRYPT_HASH_SHA2_256',
            (string) HashEnum::HASH_SHA2_384()  => 'TOMCRYPT_HASH_SHA2_384',
            (string) HashEnum::HASH_SHA2_512()  => 'TOMCRYPT_HASH_SHA2_512',
            (string) HashEnum::HASH_SHA3_224()  => 'TOMCRYPT_HASH_SHA3_224',
            (string) HashEnum::HASH_SHA3_256()  => 'TOMCRYPT_HASH_SHA3_256',
            (string) HashEnum::HASH_SHA3_384()  => 'TOMCRYPT_HASH_SHA3_384',
            (string) HashEnum::HASH_SHA3_512()  => 'TOMCRYPT_HASH_SHA3_512',
        );

        $supported = array();
        foreach ($hashes as $algo => $algoConst) {
            if (defined($algoConst)) {
                $supported[$algo] = constant($algoConst);
            }
        }
        static::$supportedAlgos['hash'] = $supported;


        // Supported cipher algorithms.
        $ciphers = array(
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
        foreach ($ciphers as $key => $value) {
            if (defined($value) && in_array(constant($value), $supported)) {
                $res[$key] = constant($value);
            }
        }
        static::$supportedAlgos['crypto'] = $res;


        // Supported MAC algorithms
        $macs  = array(
            (string) MacEnum::MAC_CMAC()    => 'TOMCRYPT_MAC_CMAC',
            (string) MacEnum::MAC_HMAC()    => 'TOMCRYPT_MAC_HMAC',
            (string) MacEnum::MAC_PMAC()    => 'TOMCRYPT_MAC_PMAC',
        );

        $supported = array();
        foreach ($macs as $algo => $algoConst) {
            if (defined($algoConst)) {
                $supported[$algo] = constant($algoConst);
            }
        }
        static::$supportedAlgos['mac'] = $supported;
    }

    protected function internalUpdate($data)
    {
        $this->data .= $data;
    }

    protected function internalFinalize()
    {
        return tomcrypt_mac_string($this->algo, $this->innerAlgo, $this->key, $this->data, true);
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        static::checkSupport();
        foreach (static::$supportedAlgos['mac'] as $algo => $algoConst) {
            $registry->addMac(
                __CLASS__,
                MacEnum::$algo(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
        }
    }
}
