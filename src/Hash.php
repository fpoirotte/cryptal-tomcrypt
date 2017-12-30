<?php

namespace fpoirotte\Cryptal\Plugins\Tomcrypt;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\AbstractHash;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Hash extends AbstractHash implements PluginInterface
{
    private $data;
    protected $algo;
    protected static $supportedAlgos = null;

    public function __construct(HashEnum $algorithm)
    {
        if (static::$supportedAlgos === null) {
            static::checkSupport();
        }

        $this->algo = $algorithm;
    }

    protected static function checkSupport()
    {
        $mapping  = array(
            (string) HashEnum::HASH_MD2()       => 'TOMCRYPT_HASH_MD2',
            (string) HashEnum::HASH_MD4()       => 'TOMCRYPT_HASH_MD4',
            (string) HashEnum::HASH_MD5()       => 'TOMCRYPT_HASH_MD5',
            (string) HashEnum::HASH_RIPEMD160() => 'TOMCRYPT_HASH_RIPEMD160',
            (string) HashEnum::HASH_SHA1()      => 'TOMCRYPT_HASH_SHA1',
            (string) HashEnum::HASH_SHA224()    => 'TOMCRYPT_HASH_SHA224',
            (string) HashEnum::HASH_SHA256()    => 'TOMCRYPT_HASH_SHA256',
            (string) HashEnum::HASH_SHA384()    => 'TOMCRYPT_HASH_SHA384',
            (string) HashEnum::HASH_SHA512()    => 'TOMCRYPT_HASH_SHA512',
        );

        $supported = array();
        foreach ($mapping as $algo => $algoConst) {
            if (defined($algoConst)) {
                $supported[$algo] = constant($algoConst);
            }
        }
        static::$supportedAlgos = $supported;
    }

    protected function internalUpdate($data)
    {
        $this->data .= $data;
    }

    protected function internalFinalize()
    {
        return tomcrypt_hash_string($this->algo, $this->data, true);
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        static::checkSupport();
        foreach (static::$supportedAlgos as $algo => $algoConst) {
            $registry->addHash(
                __CLASS__,
                HashEnum::$algo(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
        }
    }
}
