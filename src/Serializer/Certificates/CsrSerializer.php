<?php

namespace Mdanter\X509\Serializer\Certificates;

use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\Sequence;
use FG\X509\CSR\Attributes;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Util\CurveOidMapper;
use Mdanter\X509\Certificates\CertificateSubject;
use Mdanter\X509\Certificates\Csr;
use Mdanter\X509\Serializer\Signature\DerSignatureSerializer;
use Mdanter\X509\Serializer\Util\SigAlgorithmOidMapper;

class CsrSerializer
{
    const HEADER = '-----BEGIN CERTIFICATE REQUEST-----';
    const FOOTER = '-----END CERTIFICATE REQUEST-----';

    /**
     * @var DerPublicKeySerializer
     */
    private $pubKeySer;

    /**
     * @var CertificateSubjectSerializer
     */
    private $subjectSer;

    /**
     * @var DerSignatureSerializer
     */
    private $sigSer;

    /**
     * @param CertificateSubjectSerializer $subSerializer
     * @param DerPublicKeySerializer $pubKeySerializer
     * @param DerSignatureSerializer $sigSerializer
     */
    public function __construct(CertificateSubjectSerializer $subSerializer, DerPublicKeySerializer $pubKeySerializer, DerSignatureSerializer $sigSerializer)
    {
        $this->subjectSer = $subSerializer;
        $this->pubKeySer = $pubKeySerializer;
        $this->sigSer = $sigSerializer;
    }

    /**
     * @param NamedCurveFp $curve
     * @param PublicKeyInterface $publicKey
     * @return Sequence
     */
    public function getSubjectKeyASN(NamedCurveFp $curve, PublicKeyInterface $publicKey)
    {
        return new Sequence(
            new Sequence(
                new ObjectIdentifier('1.2.840.10045.2.1'),
                CurveOidMapper::getCurveOid($curve)
            ),
            new BitString($this->pubKeySer->getUncompressedKey($publicKey))
        );
    }

    /**
     * @param NamedCurveFp $curve
     * @param PublicKeyInterface $publicKey
     * @param CertificateSubject $subject
     * @return Sequence
     */
    public function getCertRequestInfoASN(NamedCurveFp $curve, PublicKeyInterface $publicKey, CertificateSubject $subject)
    {
        return new Sequence(
            new Integer(\FG\X509\CSR\CSR::CSR_VERSION_NR),
            $this->subjectSer->toAsn($subject),
            $this->getSubjectKeyASN($curve, $publicKey),
            new Attributes()
        );
    }

    /**
     * @param Csr $csr
     * @return Sequence
     */
    public function getCsrASN(Csr $csr)
    {
        return new Sequence(
            $this->getCertRequestInfoASN($csr->getCurve(), $csr->getPublicKey(), $csr->getSubject()),
            new Sequence(
                SigAlgorithmOidMapper::getSigAlgorithmOid($csr->getSigAlgorithm())
            ),
            new BitString(bin2hex($this->sigSer->serialize($csr->getSignature())))
        );
    }

    /**
     * @param Csr $csr
     * @return string
     */
    public function serialize(Csr $csr)
    {
        $payload = $this->getCsrASN($csr)->getBinary();
        $content = trim(chunk_split(base64_encode($payload), 64, PHP_EOL)).PHP_EOL;

        return self::HEADER . PHP_EOL
        . $content
        . self::FOOTER . PHP_EOL;
    }

    // TODO
    /*public function parse()
    {

    }*/
}
