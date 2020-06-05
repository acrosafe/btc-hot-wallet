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
package io.acrosafe.wallet.hot.btc.domain;

import java.io.Serializable;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import io.acrosafe.wallet.core.btc.TransactionStatus;
import io.acrosafe.wallet.core.btc.TransactionType;

@Entity
@Table(name = "transaction_record")
@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
public class TransactionRecord implements Serializable
{
    @Id
    @Column(name = "id", nullable = false)
    private String id;

    @Column(name = "transaction_id", nullable = false)
    private String transactionId;

    @Column(name = "internal_transaction_id", nullable = true)
    private String internalTransactionId;

    @Column(name = "memo", nullable = true)
    private String memo;

    @Enumerated(EnumType.STRING)
    @Column(name = "transaction_type", nullable = false)
    private TransactionType transactionType;

    @NotNull
    @Column(name = "fee", nullable = false)
    private BigInteger fee;

    @Column(name = "wallet_id", nullable = false)
    @NotNull
    private String walletId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private TransactionStatus status;

    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "transaction_id")
    private List<TransactionOutputRecord> outputs = new ArrayList<>();

    @CreatedDate
    @Column(name = "created_date", nullable = false)
    private Instant createdDate = Instant.now();

    @LastModifiedDate
    @Column(name = "last_modified_date")
    private Instant lastModifiedDate = Instant.now();

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getTransactionId()
    {
        return transactionId;
    }

    public void setTransactionId(String transactionId)
    {
        this.transactionId = transactionId;
    }

    public TransactionType getTransactionType()
    {
        return transactionType;
    }

    public void setTransactionType(TransactionType transactionType)
    {
        this.transactionType = transactionType;
    }

    public BigInteger getFee()
    {
        return fee;
    }

    public void setFee(BigInteger fee)
    {
        this.fee = fee;
    }

    public String getWalletId()
    {
        return walletId;
    }

    public void setWalletId(String walletId)
    {
        this.walletId = walletId;
    }

    public Instant getCreatedDate()
    {
        return createdDate;
    }

    public void setCreatedDate(Instant createdDate)
    {
        this.createdDate = createdDate;
    }

    public Instant getLastModifiedDate()
    {
        return lastModifiedDate;
    }

    public void setLastModifiedDate(Instant lastModifiedDate)
    {
        this.lastModifiedDate = lastModifiedDate;
    }

    public TransactionStatus getStatus()
    {
        return status;
    }

    public void setStatus(TransactionStatus status)
    {
        this.status = status;
    }

    public String getMemo()
    {
        return memo;
    }

    public void setMemo(String memo)
    {
        this.memo = memo;
    }

    public List<TransactionOutputRecord> getOutputs()
    {
        return outputs;
    }

    public void setOutputs(List<TransactionOutputRecord> outputs)
    {
        this.outputs = outputs;
    }

    public void addOutput(TransactionOutputRecord output)
    {
        outputs.add(output);
    }

    public String getInternalTransactionId()
    {
        return internalTransactionId;
    }

    public void setInternalTransactionId(String internalTransactionId)
    {
        this.internalTransactionId = internalTransactionId;
    }
}
