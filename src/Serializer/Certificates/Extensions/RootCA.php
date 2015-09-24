<?php

namespace Mdanter\X509\Serializer\Certificates\Extensions;

use FG\ASN1\Universal\Boolean;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use FG\X509\CertificateExtensions;
use Mdanter\X509\Certificates\CertificateInfo;
use Mdanter\X509\Hasher;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\X509\Serializer\Util\SigAlgorithmOidMapper;

class RootCA extends AbstractExtensions
{
    /**
     * @var DerPublicKeySerializer
     */
    private $pubKeySerializer;

    /**
     * @param DerPublicKeySerializer $derPubKeySerializer
     */
    public function __construct(DerPublicKeySerializer $derPubKeySerializer)
    {
        $this->pubKeySerializer = $derPubKeySerializer;
    }

    /**
     * @param Hasher $hasher
     * @param PublicKeyInterface $publicKey
     * @return OctetString
     */
    private function keyIdentifier(Hasher $hasher, PublicKeyInterface $publicKey)
    {
        $binary = $this->pubKeySerializer->serialize($publicKey);
        $hash = $hasher->hash($binary);
        return new OctetString($hash);
    }

    /**
     * @param CertificateInfo $certificateInfo
     * @return Sequence
     */
    public function apply(CertificateInfo $certificateInfo)
    {
        $caKey = $certificateInfo->getPublicKey();
        $caHasher = SigAlgorithmOidMapper::getHasher($certificateInfo->getSigAlgo());
        $hash = $this->keyIdentifier($caHasher, $caKey);

        $extensions = new CertificateExtensions();

        return new Sequence(
            new Sequence(
                new ObjectIdentifier('2.5.29.14'),
                new OctetString(bin2hex($hash->getBinary()))
            ),
            new Sequence(
                new ObjectIdentifier('2.5.29.35'),
                new OctetString(
                    bin2hex((new Sequence($hash))->getBinary())
                )
            ),
            new Sequence(
                new ObjectIdentifier('2.5.29.19'),
                new OctetString(
                    bin2hex((new Sequence(new Boolean(true)))->getBinary())
                )
            )
        );
    }
}
