/**
 * MIT License
 *
 * Copyright (c) 2020 acrosafe technologies
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.acrosafe.wallet.hot.btc.config;

import io.acrosafe.wallet.core.btc.Passphrase;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.text.SimpleDateFormat;
import java.util.Date;

@ConfigurationProperties(prefix = "application", ignoreUnknownFields = false)
public class ApplicationProperties
{
    private String network;
    private long fastCatchupTime;
    private int depositConfirmationNumber = 2;
    private String serviceId;
    private Passphrase passphrase;
    private String[] dnsSeeds;
    private int entropyBits = 256;
    private int securityStrength = 256;

    public String getNetwork()
    {
        return network;
    }

    public void setNetwork(String network)
    {
        this.network = network;
    }

    public int getEntropyBits()
    {
        return entropyBits;
    }

    public void setEntropyBits(int entropyBits)
    {
        this.entropyBits = entropyBits;
    }

    public long getFastCatchupTime()
    {
        return this.fastCatchupTime;
    }

    public void setFastCatchupTime(String fastCatchupTime)
    {
        try
        {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            Date date = (Date) dateFormat.parse(fastCatchupTime);
            this.fastCatchupTime = (date.getTime()) / 1000;
        }
        catch (Throwable t)
        {
            this.fastCatchupTime = 0L;
        }
    }

    public int getDepositConfirmationNumber()
    {
        return depositConfirmationNumber;
    }

    public void setDepositConfirmationNumber(int depositConfirmationNumber)
    {
        this.depositConfirmationNumber = depositConfirmationNumber;
    }

    public Passphrase getPassphrase()
    {
        return passphrase;
    }

    public void setPassphrase(String passphrase)
    {
        this.passphrase = new Passphrase(passphrase);
    }

    public String getServiceId()
    {
        return serviceId;
    }

    public void setServiceId(String serviceId)
    {
        this.serviceId = serviceId;
    }

    public String[] getDNSSeeds()
    {
        return dnsSeeds;
    }

    public void setDNSSeeds(String[] dnsSeeds)
    {
        this.dnsSeeds = dnsSeeds;
    }

    public int getSecurityStrength()
    {
        return securityStrength;
    }

    public void setSecurityStrength(int securityStrength)
    {
        this.securityStrength = securityStrength;
    }
}
