/*
 * GNU LESSER GENERAL PUBLIC LICENSE
 * Version 3, 29 June 2007
 *
 * Copyright (C) 2020 AcroBit Technologies, Ltd.
 * Everyone is permitted to copy and distribute verbatim copies
 * of this license document, but changing it is not allowed.
 *
 *
 * This version of the GNU Lesser General Public License incorporates
 * the terms and conditions of version 3 of the GNU General Public
 * License, supplemented by the additional permissions listed below.
 *
 * 0. Additional Definitions.
 *
 * As used herein, "this License" refers to version 3 of the GNU Lesser
 * General Public License, and the "GNU GPL" refers to version 3 of the GNU
 * General Public License.
 *
 * "The Library" refers to a covered work governed by this License,
 * other than an Application or a Combined Work as defined below.
 *
 * An "Application" is any work that makes use of an interface provided
 * by the Library, but which is not otherwise based on the Library.
 * Defining a subclass of a class defined by the Library is deemed a mode
 * of using an interface provided by the Library.
 *
 * A "Combined Work" is a work produced by combining or linking an
 * Application with the Library. The particular version of the Library
 * with which the Combined Work was made is also called the "Linked
 * Version".
 *
 * The "Minimal Corresponding Source" for a Combined Work means the
 * Corresponding Source for the Combined Work, excluding any source code
 * for portions of the Combined Work that, considered in isolation, are
 * based on the Application, and not on the Linked Version.
 *
 * The "Corresponding Application Code" for a Combined Work means the
 * object code and/or source code for the Application, including any data
 * and utility programs needed for reproducing the Combined Work from the
 * Application, but excluding the System Libraries of the Combined Work.
 *
 * 1. Exception to Section 3 of the GNU GPL.
 *
 * You may convey a covered work under sections 3 and 4 of this License
 * without being bound by section 3 of the GNU GPL.
 *
 * 2. Conveying Modified Versions.
 *
 * If you modify a copy of the Library, and, in your modifications, a
 * facility refers to a function or data to be supplied by an Application
 * that uses the facility (other than as an argument passed when the
 * facility is invoked), then you may convey a copy of the modified
 * version:
 *
 * a) under this License, provided that you make a good faith effort to
 * ensure that, in the event an Application does not supply the
 * function or data, the facility still operates, and performs
 * whatever part of its purpose remains meaningful, or
 *
 * b) under the GNU GPL, with none of the additional permissions of
 * this License applicable to that copy.
 *
 * 3. Object Code Incorporating Material from Library Header Files.
 *
 * The object code form of an Application may incorporate material from
 * a header file that is part of the Library. You may convey such object
 * code under terms of your choice, provided that, if the incorporated
 * material is not limited to numerical parameters, data structure
 * layouts and accessors, or small macros, inline functions and templates
 * (ten or fewer lines in length), you do both of the following:
 *
 * a) Give prominent notice with each copy of the object code that the
 * Library is used in it and that the Library and its use are
 * covered by this License.
 *
 * b) Accompany the object code with a copy of the GNU GPL and this license
 * document.
 *
 * 4. Combined Works.
 *
 * You may convey a Combined Work under terms of your choice that,
 * taken together, effectively do not restrict modification of the
 * portions of the Library contained in the Combined Work and reverse
 * engineering for debugging such modifications, if you also do each of
 * the following:
 *
 * a) Give prominent notice with each copy of the Combined Work that
 * the Library is used in it and that the Library and its use are
 * covered by this License.
 *
 * b) Accompany the Combined Work with a copy of the GNU GPL and this license
 * document.
 *
 * c) For a Combined Work that displays copyright notices during
 * execution, include the copyright notice for the Library among
 * these notices, as well as a reference directing the user to the
 * copies of the GNU GPL and this license document.
 *
 * d) Do one of the following:
 *
 * 0) Convey the Minimal Corresponding Source under the terms of this
 * License, and the Corresponding Application Code in a form
 * suitable for, and under terms that permit, the user to
 * recombine or relink the Application with a modified version of
 * the Linked Version to produce a modified Combined Work, in the
 * manner specified by section 6 of the GNU GPL for conveying
 * Corresponding Source.
 *
 * 1) Use a suitable shared library mechanism for linking with the
 * Library. A suitable mechanism is one that (a) uses at run time
 * a copy of the Library already present on the user's computer
 * system, and (b) will operate properly with a modified version
 * of the Library that is interface-compatible with the Linked
 * Version.
 *
 * e) Provide Installation Information, but only if you would otherwise
 * be required to provide such information under section 6 of the
 * GNU GPL, and only to the extent that such information is
 * necessary to install and execute a modified version of the
 * Combined Work produced by recombining or relinking the
 * Application with a modified version of the Linked Version. (If
 * you use option 4d0, the Installation Information must accompany
 * the Minimal Corresponding Source and Corresponding Application
 * Code. If you use option 4d1, you must provide the Installation
 * Information in the manner specified by section 6 of the GNU GPL
 * for conveying Corresponding Source.)
 *
 * 5. Combined Libraries.
 *
 * You may place library facilities that are a work based on the
 * Library side by side in a single library together with other library
 * facilities that are not Applications and are not covered by this
 * License, and convey such a combined library under terms of your
 * choice, if you do both of the following:
 *
 * a) Accompany the combined library with a copy of the same work based
 * on the Library, uncombined with any other library facilities,
 * conveyed under the terms of this License.
 *
 * b) Give prominent notice with the combined library that part of it
 * is a work based on the Library, and explaining where to find the
 * accompanying uncombined form of the same work.
 *
 * 6. Revised Versions of the GNU Lesser General Public License.
 *
 * The Free Software Foundation may publish revised and/or new versions
 * of the GNU Lesser General Public License from time to time. Such new
 * versions will be similar in spirit to the present version, but may
 * differ in detail to address new problems or concerns.
 *
 * Each version is given a distinguishing version number. If the
 * Library as you received it specifies that a certain numbered version
 * of the GNU Lesser General Public License "or any later version"
 * applies to it, you have the option of following the terms and
 * conditions either of that published version or of any later version
 * published by the Free Software Foundation. If the Library as you
 * received it does not specify a version number of the GNU Lesser
 * General Public License, you may choose any version of the GNU Lesser
 * General Public License ever published by the Free Software Foundation.
 *
 * If the Library as you received it specifies that a proxy can decide
 * whether future versions of the GNU Lesser General Public License shall
 * apply, that proxy's public statement of acceptance of any version is
 * permanent authorization for you to choose that version for the
 * Library.
 */
package io.acrosafe.wallet.hot.btc.service;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

import javax.annotation.PostConstruct;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import io.acrosafe.wallet.core.btc.BTCWallet;
import io.acrosafe.wallet.core.btc.WalletBalance;
import io.acrosafe.wallet.core.btc.exception.InvalidTransactionException;
import io.acrosafe.wallet.hot.btc.config.ApplicationProperties;
import io.acrosafe.wallet.hot.btc.domain.AddressRecord;
import io.acrosafe.wallet.hot.btc.domain.FeeConfigRecord;
import io.acrosafe.wallet.hot.btc.domain.TransactionOutputRecord;
import io.acrosafe.wallet.hot.btc.domain.TransactionRecord;
import io.acrosafe.wallet.hot.btc.domain.WalletRecord;
import io.acrosafe.wallet.hot.btc.exception.BroadcastFailedException;
import io.acrosafe.wallet.hot.btc.exception.CryptoException;
import io.acrosafe.wallet.hot.btc.exception.FeeRecordNotFoundException;
import io.acrosafe.wallet.hot.btc.exception.InvalidCoinSymbolException;
import io.acrosafe.wallet.hot.btc.exception.InvalidRecipientException;
import io.acrosafe.wallet.hot.btc.exception.ServiceNotReadyException;
import io.acrosafe.wallet.hot.btc.exception.WalletNotFoundException;
import io.acrosafe.wallet.hot.btc.repository.AddressRecordRepository;
import io.acrosafe.wallet.hot.btc.repository.FeeConfigRecordRepository;
import io.acrosafe.wallet.hot.btc.repository.TransactionOutputRecordRepository;
import io.acrosafe.wallet.hot.btc.repository.TransactionRecordRepository;
import io.acrosafe.wallet.hot.btc.repository.WalletRecordRepository;
import io.acrosafe.wallet.hot.btc.web.rest.request.Recipient;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;
import org.bitcoinj.wallet.listeners.WalletCoinsSentEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.ImmutableList;

import io.acrosafe.wallet.core.btc.BTCTransaction;
import io.acrosafe.wallet.core.btc.BlockChainNetwork;
import io.acrosafe.wallet.core.btc.CryptoUtils;
import io.acrosafe.wallet.core.btc.IDGenerator;
import io.acrosafe.wallet.core.btc.SeedGenerator;
import io.acrosafe.wallet.core.btc.TransactionStatus;
import io.acrosafe.wallet.core.btc.TransactionType;
import io.acrosafe.wallet.core.btc.WalletUtils;

@Service
public class WalletService
{
    // Logger
    private static final Logger logger = LoggerFactory.getLogger(WalletService.class);

    private static final ImmutableList<ChildNumber> BIP44_ACCOUNT_BTC_PATH =
            ImmutableList.of(new ChildNumber(44, true), new ChildNumber(0, true), ChildNumber.ZERO_HARDENED);

    // BTC symbol
    private static final String COIN_SYMBOL = "BTC";

    // label for default wallet
    private static final String DEFAULT_LABEL = "DEFAULT";

    // default transaction time is 2 blocks
    private static final Integer DEFAULT_NUMBER_OF_BLOCK = 2;

    @Autowired
    private SeedGenerator seedGenerator;

    @Autowired
    private ApplicationProperties applicationProperties;

    @Autowired
    private NetworkParameters networkParameters;

    @Autowired
    private BlockChainNetwork blockChainNetwork;

    @Autowired
    private FeeConfigRecordRepository feeConfigRecordRepository;

    @Autowired
    private WalletRecordRepository walletRecordRepository;

    @Autowired
    private AddressRecordRepository addressRecordRepository;

    @Autowired
    private TransactionRecordRepository transactionRecordRepository;

    @Autowired
    private TransactionOutputRecordRepository transactionOutputRecordRepository;

    private boolean isServiceReady;

    private Map<String, BTCTransaction> pendingTransactionCache = new ConcurrentHashMap<>();

    @PostConstruct
    public void initialize()
    {
        try
        {
            // initialize blockchain and restore all wallets and recovery missed transactions
            blockChainNetwork.initializeBlockChainNetwork(createDownloadProgressListener());
            restoreWallets();
            blockChainNetwork.downloadBlockChainData();
        }
        catch (Throwable t)
        {
            logger.error("failed to start BTC wallet service.", t);
        }
    }

    @Transactional
    public synchronized WalletRecord createWallet(String symbol, String label, String forwardAddress)
            throws ServiceNotReadyException, InvalidCoinSymbolException, CryptoException
    {
        if (!isServiceReady)
        {
            throw new ServiceNotReadyException("downloading blockchain data. service is not available now.");
        }

        if (StringUtils.isEmpty(symbol) || !symbol.equalsIgnoreCase(COIN_SYMBOL))
        {
            throw new InvalidCoinSymbolException("coin symbol is not valid.");
        }

        return createWallet(label, forwardAddress);
    }

    @Transactional
    public List<TransactionRecord> getTransactions(String walletId, int pageId, int size)
            throws ServiceNotReadyException, WalletNotFoundException
    {
        if (!isServiceReady)
        {
            throw new ServiceNotReadyException("downloading blockchain data. service is not available now.");
        }

        BTCWallet wallet = this.blockChainNetwork.getHotWallet(walletId);
        if (wallet == null)
        {
            throw new WalletNotFoundException("failed to find wallet. id = " + walletId);
        }

        Pageable pageable = PageRequest.of(pageId, size, Sort.by(Sort.Direction.ASC, "CreatedDate"));
        List<TransactionRecord> records = this.transactionRecordRepository.findAllByWalletId(walletId, pageable);

        return records;
    }

    @Transactional
    public WalletRecord getWallet(String walletId) throws WalletNotFoundException, ServiceNotReadyException
    {
        if (!isServiceReady)
        {
            throw new ServiceNotReadyException("downloading blockchain data. service is not available now.");
        }

        WalletRecord walletRecord = this.walletRecordRepository.findById(walletId).orElse(null);
        BTCWallet wallet = this.blockChainNetwork.getHotWallet(walletId);
        if (wallet == null || walletRecord == null)
        {
            throw new WalletNotFoundException("wallet doesn't exist. id = " + walletId);
        }

        return walletRecord;
    }

    @Transactional
    public List<WalletRecord> getWallets(int pageId, int size) throws ServiceNotReadyException
    {
        if (!isServiceReady)
        {
            throw new ServiceNotReadyException("downloading blockchain data. service is not available now.");
        }

        Pageable pageable = PageRequest.of(pageId, size, Sort.by(Sort.Direction.DESC, "CreatedDate"));
        Page<WalletRecord> records = this.walletRecordRepository.findAll(pageable);

        return records.toList();
    }

    @Transactional
    public synchronized AddressRecord refreshReceivingAddress(String walletId, String coinSymbol, String label)
            throws WalletNotFoundException, ServiceNotReadyException, InvalidCoinSymbolException
    {
        if (!isServiceReady)
        {
            throw new ServiceNotReadyException("downloading blockchain data. service is not available now.");
        }

        BTCWallet wallet = this.blockChainNetwork.getHotWallet(walletId);
        if (wallet == null)
        {
            throw new WalletNotFoundException("failed to find wallet. id = " + walletId);
        }

        if (StringUtils.isEmpty(coinSymbol) || !coinSymbol.equalsIgnoreCase(COIN_SYMBOL))
        {
            throw new InvalidCoinSymbolException("coin symbol is not valid.");
        }

        Address address = wallet.freshReceiveAddress();
        AddressRecord record = this.addressRecordRepository.findById(address.toString()).orElse(null);
        while (record != null)
        {
            address = wallet.freshReceiveAddress();
            record = this.addressRecordRepository.findById(address.toString()).orElse(null);
        }

        logger.info("new receiving address generated. address = {}", address.toString());
        wallet.addWatchedAddress(address);

        AddressRecord addressRecord = new AddressRecord();
        addressRecord.setCreatedDate(Instant.now());
        addressRecord.setWalletId(walletId);
        addressRecord.setReceiveAddress(address.toString());
        addressRecord.setLabel(label);

        this.addressRecordRepository.save(addressRecord);

        return addressRecord;
    }

    @Transactional
    public WalletBalance getBalance(String walletId) throws ServiceNotReadyException, WalletNotFoundException
    {
        if (!isServiceReady)
        {
            throw new ServiceNotReadyException("downloading blockchain data. service is not available now.");
        }

        BTCWallet wallet = this.blockChainNetwork.getHotWallet(walletId);
        if (wallet == null)
        {
            throw new WalletNotFoundException("wallet doesn't exist. id = " + walletId);
        }

        Context.propagate(this.blockChainNetwork.getContext());
        WalletBalance balance = wallet.getWalletBalance();
        return balance;
    }

    @Transactional
    public synchronized String send(String walletId, String coinSymbol, List<Recipient> recipients, Integer numberOfBlock,
            String memo, String internalTransactionId) throws ServiceNotReadyException, WalletNotFoundException,
            InvalidCoinSymbolException, InvalidRecipientException, FeeRecordNotFoundException, CryptoException,
            InsufficientMoneyException, BroadcastFailedException, InvalidTransactionException, ExecutionException
    {
        if (!isServiceReady)
        {
            throw new ServiceNotReadyException("downloading blockchain data. service is not available now.");
        }

        BTCWallet wallet = this.blockChainNetwork.getHotWallet(walletId);
        if (wallet == null)
        {
            throw new WalletNotFoundException("failed to find wallet in cache. id = " + walletId);
        }

        WalletRecord record = this.walletRecordRepository.findById(walletId).orElse(null);
        if (record == null)
        {
            throw new WalletNotFoundException("failed to find wallet record in db. id = " + walletId);
        }

        if (StringUtils.isEmpty(coinSymbol) || !coinSymbol.equalsIgnoreCase(COIN_SYMBOL))
        {
            throw new InvalidCoinSymbolException("coin symbol is not valid.");
        }

        if (recipients == null || recipients.size() == 0)
        {
            throw new InvalidRecipientException("receipients cannot be null or empty.");
        }

        if (numberOfBlock == null || numberOfBlock <= 0)
        {
            numberOfBlock = DEFAULT_NUMBER_OF_BLOCK;
        }

        final FeeConfigRecord feeRecord = this.feeConfigRecordRepository.findById(numberOfBlock).orElse(null);
        if (feeRecord == null)
        {
            throw new FeeRecordNotFoundException(
                    "failed to find the fee record based on given number of block. numberOfBlock = " + numberOfBlock);
        }

        Context.propagate(this.blockChainNetwork.getContext());

        Transaction transaction = new Transaction(networkParameters);
        for (Recipient recipient : recipients)
        {
            final Address address = Address.fromString(networkParameters, recipient.getAddress());
            transaction.addOutput(Coin.valueOf(Long.parseLong(recipient.getAmount())), ScriptBuilder.createOutputScript(address));
        }

        SendRequest request = SendRequest.forTx(transaction);
        request.feePerKb = Coin.valueOf(feeRecord.getFeePerKb().longValue());
        request.ensureMinRequiredFee = false;
        wallet.completeTx(request);

        final String id = IDGenerator.randomUUID().toString();
        final Instant createdDate = Instant.now();
        TransactionRecord transactionRecord = new TransactionRecord();
        transactionRecord.setStatus(TransactionStatus.SIGNED);
        transactionRecord.setTransactionType(TransactionType.WITHDRAWAL);
        transactionRecord.setFee(BigInteger.valueOf(request.tx.getFee().longValue()));
        transactionRecord.setWalletId(walletId);
        transactionRecord.setLastModifiedDate(createdDate);
        transactionRecord.setTransactionId(request.tx.getTxId().toString());
        transactionRecord.setCreatedDate(createdDate);
        transactionRecord.setId(id);

        if (!StringUtils.isEmpty(memo))
        {
            transactionRecord.setMemo(memo);
        }

        if (!StringUtils.isEmpty(internalTransactionId))
        {
            transactionRecord.setInternalTransactionId(internalTransactionId);
        }

        List<TransactionOutput> outputs = transaction.getOutputs();
        if (outputs != null && outputs.size() != 0)
        {
            for (TransactionOutput output : outputs)
            {
                if (!output.isMineOrWatched(wallet))
                {
                    final String address = output.getScriptPubKey().getToAddress(networkParameters).toString();
                    final int index = output.getIndex();
                    final long amount = output.getValue().longValue();
                    logger.info("signing transaction, adding output to transaction record. address = {}, index = {}, value = {}",
                            address, index, amount);
                    TransactionOutputRecord transactionOutputRecord = new TransactionOutputRecord();
                    transactionOutputRecord.setId(IDGenerator.randomUUID().toString());
                    transactionOutputRecord.setAmount(BigInteger.valueOf(amount));
                    transactionOutputRecord.setCreatedDate(Instant.now());
                    transactionOutputRecord.setOutputIndex(index);
                    transactionOutputRecord.setTransactionId(id);
                    transactionOutputRecord.setDestination(address);

                    transactionRecord.addOutput(transactionOutputRecord);
                }
            }
        }

        try
        {
            ListenableFuture<Transaction> future = this.blockChainNetwork.broadcastTransaction(request.tx);
            final Transaction result = future.get();

            if (result == null)
            {
                transactionRecord.setStatus(TransactionStatus.FAILED);
                transactionRecordRepository.save(transactionRecord);
                throw new BroadcastFailedException("broadcasting failed. result is null.");
            }
            Futures.addCallback(future, new FutureCallback<Transaction>()
            {
                @Override
                public void onSuccess(Transaction transaction)
                {
                    if (record != null)
                    {
                        final String transactionId = transaction.getTxId().toString();
                        if (!pendingTransactionCache.containsKey(transactionId))
                        {
                            BTCTransaction btcTransaction = new BTCTransaction(walletId, transaction);
                            btcTransaction.addTransactionConfidenceListener(new BTCTransactionConfidenceEventListener());

                            pendingTransactionCache.put(transactionId, btcTransaction);
                        }
                    }
                }

                @Override
                public void onFailure(Throwable throwable)
                {
                    if (record != null)
                    {
                        transactionRecord.setStatus(TransactionStatus.FAILED);
                        transactionRecordRepository.save(transactionRecord);
                    }
                }
            }, MoreExecutors.directExecutor());

            return result.getTxId().toString();
        }
        catch (InterruptedException | ExecutionException e)
        {
            if (record != null)
            {
                transactionRecord.setStatus(TransactionStatus.UNCONFIRMED);
                transactionRecordRepository.save(transactionRecord);
            }
            throw new BroadcastFailedException("broadcast failed.", e);
        }
    }

    private WalletRecord createWallet(String label, String forwardAddress) throws CryptoException
    {
        Context.propagate(this.blockChainNetwork.getContext());

        final String id = IDGenerator.randomUUID().toString();
        final Instant createdDate = Instant.now();
        final long creationTimeInSeconds = System.currentTimeMillis() / 1000;

        // Generates seeds
        final String serviceId = this.applicationProperties.getServiceId();
        final int entropyBits = this.applicationProperties.getEntropyBits();
        final int securityStrength = this.applicationProperties.getSecurityStrength();
        final byte[] ownerSeed = this.seedGenerator.getSeed(serviceId, securityStrength, entropyBits);

        DeterministicSeed deterministicSeed = this.seedGenerator.restoreDeterministicSeed(ownerSeed, StringUtils.EMPTY,
                MnemonicCode.BIP39_STANDARDISATION_TIME_SECS);

        DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(deterministicSeed)
                .outputScriptType(Script.ScriptType.P2WPKH).accountPath(BIP44_ACCOUNT_BTC_PATH).build();
        KeyChainGroup keyChainGroup = KeyChainGroup.builder(networkParameters).addChain(chain).build();

        BTCWallet wallet = new BTCWallet(id, networkParameters, keyChainGroup);
        wallet.addWalletListeners(new BTCWalletCoinsSentEventListener(), new BTCWalletCoinsReceivedEventListener());

        final byte[] ownerSpec = CryptoUtils.generateIVParameterSpecBytes();
        final String encodedOwnerSpec = Base64.getEncoder().encodeToString(ownerSpec);
        final byte[] ownerSalt = CryptoUtils.generateSaltBytes();
        final String encodedOwnerSalt = Base64.getEncoder().encodeToString(ownerSalt);

        String encryptedOwnerSeed = null;

        try
        {
            encryptedOwnerSeed =
                    CryptoUtils.encrypt(applicationProperties.getPassphrase().getStringValue(), ownerSeed, ownerSpec, ownerSalt);
        }
        catch (Throwable t)
        {
            // this shouldn't happen at all.
            throw new CryptoException("Invalid crypto operation.", t);
        }

        WalletRecord walletRecord = new WalletRecord();
        walletRecord.setId(id);
        walletRecord.setSeed(encryptedOwnerSeed);
        walletRecord.setSpec(encodedOwnerSpec);
        walletRecord.setSalt(encodedOwnerSalt);
        walletRecord.setCreatedDate(createdDate);
        walletRecord.setEnabled(true);
        walletRecord.setLabel(label);
        walletRecord.setTimestamp(creationTimeInSeconds);

        walletRecordRepository.save(walletRecord);
        this.blockChainNetwork.addHotWallet(wallet);

        logger.info("new hot wallet created. id = {}, createdDate = {}", id, createdDate);

        return walletRecord;
    }

    private DownloadProgressTracker createDownloadProgressListener() throws BlockStoreException
    {
        return new DownloadProgressTracker()
        {
            @Override
            public void progress(double pct, int blocksSoFar, Date date)
            {
                super.progress(pct, blocksSoFar, date);
                isServiceReady = false;

                int remainder = ((int) pct) % 5;
                if (remainder == 0)
                {
                    logger.info("downloading blockchain data now. percentage = {}%, {} block left, date = {}", (int) pct,
                            blocksSoFar, date);
                }
            }

            @Override
            public void doneDownload()
            {
                logger.info("All blocks have been downloaded. BTC wallet service is available.");
                isServiceReady = true;

                restorePendingTransactions();
            }
        };
    }

    private void restorePendingTransactions()
    {
        List<TransactionRecord> transactionRecords =
                this.transactionRecordRepository.findAllByStatus(TransactionStatus.UNCONFIRMED);

        List<TransactionRecord> updatedRecords = new ArrayList<>();
        for (TransactionRecord transactionRecord : transactionRecords)
        {
            BTCWallet wallet = this.blockChainNetwork.getHotWallet(transactionRecord.getWalletId());
            Transaction transaction =
                    wallet.getTransaction(Sha256Hash.wrap(Utils.HEX.decode(transactionRecord.getTransactionId())));

            if (transaction == null)
            {
                logger.warn("transaction {} is not in wallet cache.", transactionRecord.getTransactionId());
            }
            else
            {
                final TransactionConfidence.ConfidenceType type = transaction.getConfidence().getConfidenceType();
                final int depth = transaction.getConfidence().getDepthInBlocks();

                if (type == TransactionConfidence.ConfidenceType.PENDING || (type == TransactionConfidence.ConfidenceType.BUILDING
                        && (depth < applicationProperties.getDepositConfirmationNumber())))
                {
                    BTCTransaction btcTransaction = new BTCTransaction(wallet.getWalletId(), transaction);
                    btcTransaction.addTransactionConfidenceListener(new BTCTransactionConfidenceEventListener());

                    pendingTransactionCache.put(btcTransaction.getTransactionId(), btcTransaction);
                }
                else
                {
                    transactionRecord.setStatus(
                            WalletUtils.getBlockChainTransactionStatus(type, transaction.getConfidence().getDepthInBlocks(),
                                    applicationProperties.getDepositConfirmationNumber()));
                    transactionRecord.setLastModifiedDate(Instant.now());
                    updatedRecords.add(transactionRecord);
                }
            }

            logger.info("restore all the pending transactions. size = {}", pendingTransactionCache.size());

            if (updatedRecords != null && updatedRecords.size() != 0)
            {
                transactionRecordRepository.saveAll(updatedRecords);
            }
        }
    }

    private void restoreWallets() throws CryptoException
    {
        List<WalletRecord> walletRecords = this.walletRecordRepository.findAll();
        if (walletRecords != null && walletRecords.size() != 0)
        {
            for (WalletRecord walletRecord : walletRecords)
            {
                try
                {
                    final String id = walletRecord.getId();
                    final long creationTimeInSeconds = walletRecord.getTimestamp();
                    final String encryptedOwnerSeed = walletRecord.getSeed();

                    final byte[] ownerSalt = Base64.getDecoder().decode(walletRecord.getSalt());
                    final byte[] ownerSpec = Base64.getDecoder().decode(walletRecord.getSpec());

                    final byte[] ownerSeed = CryptoUtils.decrypt(this.applicationProperties.getPassphrase().getStringValue(),
                            encryptedOwnerSeed, ownerSpec, ownerSalt);

                    DeterministicSeed deterministicOwnerSeed =
                            this.seedGenerator.restoreDeterministicSeed(ownerSeed, StringUtils.EMPTY, creationTimeInSeconds);
                    DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(deterministicOwnerSeed)
                            .outputScriptType(Script.ScriptType.P2WPKH).accountPath(BIP44_ACCOUNT_BTC_PATH).build();
                    KeyChainGroup keyChainGroup = KeyChainGroup.builder(networkParameters).addChain(chain).build();

                    BTCWallet wallet = new BTCWallet(id, networkParameters, keyChainGroup);
                    wallet.addWalletListeners(new BTCWalletCoinsSentEventListener(), new BTCWalletCoinsReceivedEventListener());

                    this.blockChainNetwork.addHotWallet(wallet);
                }
                catch (Throwable t)
                {
                    // this shouldn't happen at all.
                    throw new CryptoException("Invalid crypto operation.", t);
                }
            }
        }
        else
        {
            logger.warn("no wallet found. syncing the blockchain data. this might take long time.");
        }
    }

    private void updateTransaction(TransactionConfidence confidence)
    {
        TransactionConfidence.ConfidenceType type = confidence.getConfidenceType();
        switch (type)
        {
        case BUILDING:
        {
            if (confidence.getDepthInBlocks() >= this.applicationProperties.getDepositConfirmationNumber())
            {
                final String transactionId = confidence.getTransactionHash().toString();
                TransactionRecord transactionRecord =
                        transactionRecordRepository.findFirstByTransactionId(transactionId).orElse(null);

                if (transactionRecord != null)
                {
                    transactionRecord.setStatus(TransactionStatus.CONFIRMED);
                    transactionRecord.setLastModifiedDate(Instant.now());

                    transactionRecordRepository.save(transactionRecord);

                    // remove transaction id
                    BTCTransaction transaction = pendingTransactionCache.get(transactionId);
                    if (transaction != null)
                    {
                        pendingTransactionCache.get(transactionId).removeTransactionConfidenceListener();
                        pendingTransactionCache.remove(transactionId);
                    }
                }
            }
            break;
        }
        case PENDING:
        {
            break;
        }
        case IN_CONFLICT:
        case DEAD:
        case UNKNOWN:
        default:
        {
            final String transactionId = confidence.getTransactionHash().toString();
            TransactionRecord transactionRecord =
                    transactionRecordRepository.findFirstByTransactionId(transactionId).orElse(null);

            if (transactionRecord != null)
            {
                transactionRecord.setStatus(TransactionStatus.FAILED);
                transactionRecord.setLastModifiedDate(Instant.now());

                transactionRecordRepository.save(transactionRecord);

                // remove transaction id
                pendingTransactionCache.get(transactionId).removeTransactionConfidenceListener();
                pendingTransactionCache.remove(transactionId);
            }
        }
        }

    }

    /**
     * Implementation of coins received event listener
     */
    public class BTCWalletCoinsReceivedEventListener implements WalletCoinsReceivedEventListener
    {

        @Override
        public void onCoinsReceived(Wallet wallet, Transaction transaction, Coin prevBalance, Coin newBalance)
        {
            final String walletId = wallet.getDescription();
            final Coin diff = newBalance.subtract(prevBalance);
            final String transactionId = transaction.getTxId().toString();

            if (diff.isGreaterThan(Coin.ZERO))
            {
                logger.info("new deposite received. transactionId = {}, walletId = {}, amount = {}", transactionId, walletId,
                        diff);

                TransactionRecord transactionRecord =
                        transactionRecordRepository.findFirstByTransactionId(transactionId).orElse(null);

                // If record is not saved in db
                if (transactionRecord == null)
                {
                    final TransactionConfidence.ConfidenceType confidenceType = transaction.getConfidence().getConfidenceType();
                    final int depthInBlocks = transaction.getConfidence().getDepthInBlocks();

                    TransactionStatus status = WalletUtils.getBlockChainTransactionStatus(confidenceType, depthInBlocks,
                            applicationProperties.getDepositConfirmationNumber());

                    logger.info("transaction {} is not in DB. confidencyType = {}, depthInBlocks = {}", transactionId,
                            confidenceType, depthInBlocks);
                    TransactionRecord record = new TransactionRecord();
                    record.setId(IDGenerator.randomUUID().toString());
                    record.setTransactionId(transactionId);
                    record.setLastModifiedDate(transaction.getUpdateTime().toInstant());
                    record.setWalletId(walletId);
                    record.setFee(BigInteger.ZERO);
                    record.setTransactionType(TransactionType.DEPOSIT);
                    record.setStatus(status);
                    if (!StringUtils.isEmpty(transaction.getMemo()))
                    {
                        record.setMemo(transaction.getMemo());
                    }

                    List<TransactionOutput> outputs = transaction.getOutputs();
                    if (outputs != null && outputs.size() != 0)
                    {
                        for (TransactionOutput output : outputs)
                        {
                            if (output.isMineOrWatched(wallet))
                            {
                                final String address = output.getScriptPubKey().getToAddress(networkParameters).toString();
                                final int index = output.getIndex();
                                final long amount = output.getValue().longValue();
                                logger.info(
                                        "transaction record doesn't exist. adding output to transaction record. address = {}, index = {}, value = {}",
                                        address, index, amount);
                                TransactionOutputRecord transactionOutputRecord = new TransactionOutputRecord();
                                transactionOutputRecord.setId(IDGenerator.randomUUID().toString());
                                transactionOutputRecord.setAmount(BigInteger.valueOf(amount));
                                transactionOutputRecord.setCreatedDate(Instant.now());
                                transactionOutputRecord.setOutputIndex(index);
                                transactionOutputRecord.setTransactionId(record.getId());
                                transactionOutputRecord.setDestination(address);

                                record.addOutput(transactionOutputRecord);
                            }
                        }
                    }

                    transactionRecordRepository.save(record);

                    if (status == TransactionStatus.UNCONFIRMED && !pendingTransactionCache.containsKey(transactionId))
                    {
                        BTCTransaction btcTransaction = new BTCTransaction(wallet.getDescription(), transaction);
                        btcTransaction.addTransactionConfidenceListener(new BTCTransactionConfidenceEventListener());

                        pendingTransactionCache.put(transactionId, btcTransaction);
                    }
                }
                else
                {
                    logger.info("transaction record found in DB. transactionId = {}, walletId = {}, balance = {}", transactionId,
                            walletId, diff);

                    if (transactionRecord.getTransactionType() != TransactionType.WITHDRAWAL)
                    {
                        List<TransactionOutput> outputs = transaction.getOutputs();
                        if (outputs != null && outputs.size() != 0)
                        {
                            final String internalTransactionId = transactionRecord.getId();
                            for (TransactionOutput output : outputs)
                            {
                                if (output.isMineOrWatched(wallet))
                                {
                                    final int index = output.getIndex();
                                    final TransactionOutputRecord existingTransactionOutputRecord =
                                            transactionOutputRecordRepository
                                                    .findFirstByTransactionIdAndOutputIndex(internalTransactionId, index)
                                                    .orElse(null);

                                    final String address = output.getScriptPubKey().getToAddress(networkParameters).toString();
                                    final long amount = output.getValue().longValue();
                                    if (existingTransactionOutputRecord == null)
                                    {
                                        logger.info(
                                                "transaction output doesn't exist. adding output to transaction record. address = {}, index = {}, value = {}",
                                                address, index, amount);
                                        TransactionOutputRecord transactionOutputRecord = new TransactionOutputRecord();
                                        transactionOutputRecord.setId(IDGenerator.randomUUID().toString());
                                        transactionOutputRecord.setAmount(BigInteger.valueOf(amount));
                                        transactionOutputRecord.setCreatedDate(Instant.now());
                                        transactionOutputRecord.setOutputIndex(index);
                                        transactionOutputRecord.setTransactionId(internalTransactionId);
                                        transactionOutputRecord.setDestination(address);

                                        transactionOutputRecordRepository.save(transactionOutputRecord);
                                    }
                                    else
                                    {
                                        logger.info("transaction output already existed. address = {}, index = {}, value = {}",
                                                address, index, amount);
                                    }
                                }
                                else
                                {
                                    logger.info("transaction {} output {} is not mine.", transactionId, output.getIndex());
                                }
                            }
                        }
                    }
                    else
                    {
                        logger.info("found change address. transaction type is withdrawal.");
                    }

                    if (transactionRecord.getStatus() == TransactionStatus.UNCONFIRMED)
                    {
                        if (!pendingTransactionCache.containsKey(transactionId))
                        {
                            BTCTransaction btcTransaction = new BTCTransaction(wallet.getDescription(), transaction);
                            btcTransaction.addTransactionConfidenceListener(new BTCTransactionConfidenceEventListener());

                            pendingTransactionCache.put(transactionId, btcTransaction);
                        }
                    }
                }
            }
        }

    }

    public class BTCWalletCoinsSentEventListener implements WalletCoinsSentEventListener
    {
        @Override
        public void onCoinsSent(Wallet wallet, Transaction transaction, Coin prevBalance, Coin newBalance)
        {
            final String walletId = wallet.getDescription();
            final Coin diff = newBalance.subtract(prevBalance);
            final String transactionId = transaction.getTxId().toString();
            logger.info("new withdrawal received. transactionId = {}, walletId = {}, balance = {}, memo = {}, fee = {}",
                    transactionId, walletId, diff, transaction.getMemo(), transaction.getFee());

            final TransactionConfidence.ConfidenceType confidenceType = transaction.getConfidence().getConfidenceType();
            final int depthInBlocks = transaction.getConfidence().getDepthInBlocks();

            TransactionStatus status = WalletUtils.getBlockChainTransactionStatus(confidenceType, depthInBlocks,
                    applicationProperties.getDepositConfirmationNumber());

            TransactionRecord transactionRecord =
                    transactionRecordRepository.findFirstByTransactionId(transactionId).orElse(null);
            if (transactionRecord == null)
            {
                TransactionRecord record = new TransactionRecord();
                record.setId(IDGenerator.randomUUID().toString());
                record.setTransactionId(transactionId);
                record.setLastModifiedDate(transaction.getUpdateTime().toInstant());
                record.setWalletId(walletId);
                record.setFee(BigInteger.valueOf(transaction.getFee().longValue()));
                record.setTransactionType(TransactionType.WITHDRAWAL);
                record.setStatus(status);
                if (!StringUtils.isEmpty(transaction.getMemo()))
                {
                    record.setMemo(transaction.getMemo());
                }

                List<TransactionOutput> outputs = transaction.getOutputs();
                if (outputs != null && outputs.size() != 0)
                {
                    for (TransactionOutput output : outputs)
                    {
                        if (!output.isMineOrWatched(wallet))
                        {
                            final String address = output.getScriptPubKey().getToAddress(networkParameters).toString();
                            final int index = output.getIndex();
                            final long amount = output.getValue().longValue();
                            logger.info(
                                    "transaction record doesn't exist. adding output to transaction record. address = {}, index = {}, value = {}",
                                    address, index, amount);
                            TransactionOutputRecord transactionOutputRecord = new TransactionOutputRecord();
                            transactionOutputRecord.setId(IDGenerator.randomUUID().toString());
                            transactionOutputRecord.setAmount(BigInteger.valueOf(amount));
                            transactionOutputRecord.setCreatedDate(Instant.now());
                            transactionOutputRecord.setOutputIndex(index);
                            transactionOutputRecord.setTransactionId(record.getId());
                            transactionOutputRecord.setDestination(address);

                            record.addOutput(transactionOutputRecord);
                        }
                    }
                }

                transactionRecordRepository.save(record);

            }
            else
            {
                if (transactionRecord.getStatus() == TransactionStatus.UNCONFIRMED)
                {
                    if (!pendingTransactionCache.containsKey(transactionId))
                    {
                        BTCTransaction btcTransaction = new BTCTransaction(wallet.getDescription(), transaction);
                        btcTransaction.addTransactionConfidenceListener(new BTCTransactionConfidenceEventListener());

                        pendingTransactionCache.put(transactionId, btcTransaction);
                    }
                }
            }
        }
    }

    public class BTCTransactionConfidenceEventListener implements TransactionConfidence.Listener
    {
        @Override
        public void onConfidenceChanged(TransactionConfidence confidence, ChangeReason reason)
        {
            updateTransaction(confidence);
        }
    }
}
