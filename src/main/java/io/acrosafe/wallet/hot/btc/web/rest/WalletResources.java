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
package io.acrosafe.wallet.hot.btc.web.rest;

import java.util.List;

import io.acrosafe.wallet.core.btc.WalletBalance;
import io.acrosafe.wallet.hot.btc.domain.AddressRecord;
import io.acrosafe.wallet.hot.btc.domain.TransactionOutputRecord;
import io.acrosafe.wallet.hot.btc.domain.TransactionRecord;
import io.acrosafe.wallet.hot.btc.domain.WalletRecord;
import io.acrosafe.wallet.hot.btc.exception.CryptoException;
import io.acrosafe.wallet.hot.btc.exception.FeeRecordNotFoundException;
import io.acrosafe.wallet.hot.btc.exception.InvalidCoinSymbolException;
import io.acrosafe.wallet.hot.btc.exception.InvalidRecipientException;
import io.acrosafe.wallet.hot.btc.exception.ServiceNotReadyException;
import io.acrosafe.wallet.hot.btc.exception.WalletNotFoundException;
import io.acrosafe.wallet.hot.btc.service.WalletService;
import io.acrosafe.wallet.hot.btc.web.rest.request.CreateWalletRequest;
import io.acrosafe.wallet.hot.btc.web.rest.request.GetReceiveAddressRequest;
import io.acrosafe.wallet.hot.btc.web.rest.request.SendCoinRequest;
import io.acrosafe.wallet.hot.btc.web.rest.response.Balance;
import io.acrosafe.wallet.hot.btc.web.rest.response.CreateWalletResponse;
import io.acrosafe.wallet.hot.btc.web.rest.response.GetReceiveAddressResponse;
import io.acrosafe.wallet.hot.btc.web.rest.response.GetTransactionListResponse;
import io.acrosafe.wallet.hot.btc.web.rest.response.GetTransactionResponse;
import io.acrosafe.wallet.hot.btc.web.rest.response.GetWalletResponse;
import io.acrosafe.wallet.hot.btc.web.rest.response.GetWalletsResponse;
import io.acrosafe.wallet.hot.btc.web.rest.response.Result;
import io.acrosafe.wallet.hot.btc.web.rest.response.SendCoinResponse;
import io.acrosafe.wallet.hot.btc.web.rest.response.TransactionOutput;
import org.bitcoinj.core.InsufficientMoneyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import io.acrosafe.wallet.core.btc.TransactionType;
import io.acrosafe.wallet.core.btc.WalletUtils;

@Controller
@RequestMapping("/api/v1/btc/wallet")
public class WalletResources
{
    // Logger
    private static final Logger logger = LoggerFactory.getLogger(WalletResources.class);

    @Autowired
    private WalletService service;

    @PostMapping("/new")
    public ResponseEntity<CreateWalletResponse> createWallet(@RequestBody CreateWalletRequest request)
    {
        CreateWalletResponse response = new CreateWalletResponse();
        try
        {
            WalletRecord record = this.service.createWallet(request.getSymbol(), request.getLabel(), request.getForwardAddress());
            response.setCreatedDate(record.getCreatedDate());
            response.setEnabled(record.isEnabled());
            response.setId(record.getId());
            response.setCreationTime(record.getTimestamp());
            response.setEncryptedSeed(record.getSeed());
            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (ServiceNotReadyException e)
        {
            response.setResultCode(Result.SERVICE_NOT_READY.getCode());
            response.setResult(Result.SERVICE_NOT_READY);
            return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (InvalidCoinSymbolException e)
        {
            response.setResultCode(Result.INVALID_COIN_SYMBOL.getCode());
            response.setResult(Result.INVALID_COIN_SYMBOL);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (CryptoException e)
        {
            response.setResultCode(Result.INVALID_CRYPTO_OPERATION.getCode());
            response.setResult(Result.INVALID_CRYPTO_OPERATION);
            return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (Throwable e)
        {
            logger.error("failed to create new wallet.", e);
            response.setResultCode(Result.UNKNOWN_ERROR.getCode());
            response.setResult(Result.UNKNOWN_ERROR);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{walletId}/transaction/all")
    public ResponseEntity<GetTransactionListResponse> getTransactions(@PathVariable String walletId,
            @RequestParam(required = true, defaultValue = "0") int pageId,
            @RequestParam(required = false, defaultValue = "100") int size)
    {
        GetTransactionListResponse response = new GetTransactionListResponse();
        try
        {
            List<TransactionRecord> transactionRecords = this.service.getTransactions(walletId, pageId, size);
            if (transactionRecords != null && transactionRecords.size() != 0)
            {
                for (TransactionRecord transactionRecord : transactionRecords)
                {
                    GetTransactionResponse getTransactionOutputResponse = new GetTransactionResponse();
                    getTransactionOutputResponse.setCreatedDate(transactionRecord.getCreatedDate());
                    getTransactionOutputResponse.setFee(transactionRecord.getFee().toString());
                    getTransactionOutputResponse.setStatus(transactionRecord.getStatus().getStatus());
                    getTransactionOutputResponse.setTransactionId(transactionRecord.getTransactionId());
                    getTransactionOutputResponse.setWalletId(walletId);
                    if (transactionRecord.getTransactionType() == TransactionType.DEPOSIT)
                    {
                        getTransactionOutputResponse.setType(TransactionType.DEPOSIT);
                    }
                    else
                    {
                        getTransactionOutputResponse.setType(TransactionType.WITHDRAWAL);
                    }
                    for (TransactionOutputRecord transactionOutputRecord : transactionRecord.getOutputs())
                    {
                        TransactionOutput output = new TransactionOutput();
                        output.setIndex(transactionOutputRecord.getOutputIndex());
                        output.setReceiveAddress(transactionOutputRecord.getDestination());
                        output.setValue(WalletUtils.toStandardUnit(transactionOutputRecord.getAmount()).toPlainString());
                        output.setValueInSmallestUnit(transactionOutputRecord.getAmount().toString());

                        getTransactionOutputResponse.addOutput(output);
                    }

                    response.addTransaction(getTransactionOutputResponse);
                }

                response.setSize(transactionRecords.size());
            }

            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (WalletNotFoundException e)
        {
            response.setResultCode(Result.WALLET_NOT_FOUND.getCode());
            response.setResult(Result.WALLET_NOT_FOUND);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (ServiceNotReadyException e)
        {
            response.setResultCode(Result.SERVICE_NOT_READY.getCode());
            response.setResult(Result.SERVICE_NOT_READY);
            return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (Throwable e)
        {
            logger.error("failed to get transaction.", e);
            response.setResultCode(Result.UNKNOWN_ERROR.getCode());
            response.setResult(Result.UNKNOWN_ERROR);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{walletId}/balance")
    public ResponseEntity<GetWalletResponse> getBalance(@PathVariable String walletId)
    {
        GetWalletResponse response = new GetWalletResponse();
        try
        {
            WalletBalance walletBalance = this.service.getBalance(walletId);

            Balance balance = new Balance();
            balance.setAvailable(walletBalance.getAvailable());
            balance.setEstimated(walletBalance.getEstimated());

            response.setId(walletId);
            response.setBalance(balance);

            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (ServiceNotReadyException e)
        {
            response.setResultCode(Result.SERVICE_NOT_READY.getCode());
            response.setResult(Result.SERVICE_NOT_READY);
            return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (WalletNotFoundException e)
        {
            response.setResultCode(Result.WALLET_NOT_FOUND.getCode());
            response.setResult(Result.WALLET_NOT_FOUND);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (Throwable e)
        {
            logger.error("failed to get wallet balance.", e);
            response.setResultCode(Result.UNKNOWN_ERROR.getCode());
            response.setResult(Result.UNKNOWN_ERROR);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{walletId}")
    public ResponseEntity<GetWalletResponse> getWallet(@PathVariable String walletId)
    {
        GetWalletResponse response = new GetWalletResponse();
        try
        {
            WalletRecord detail = this.service.getWallet(walletId);
            WalletBalance walletBalance = this.service.getBalance(walletId);

            Balance balance = new Balance();
            balance.setEstimated(walletBalance.getEstimated());
            balance.setAvailable(walletBalance.getAvailable());

            response.setId(detail.getId());
            response.setCreatedDate(detail.getCreatedDate());
            response.setEnabled(detail.isEnabled());
            response.setBalance(balance);
            response.setLabel(detail.getLabel());

            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (ServiceNotReadyException e)
        {
            response.setResultCode(Result.SERVICE_NOT_READY.getCode());
            response.setResult(Result.SERVICE_NOT_READY);
            return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (WalletNotFoundException e)
        {
            response.setResultCode(Result.WALLET_NOT_FOUND.getCode());
            response.setResult(Result.WALLET_NOT_FOUND);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (Throwable e)
        {
            logger.error("failed to get wallet.", e);
            response.setResultCode(Result.UNKNOWN_ERROR.getCode());
            response.setResult(Result.UNKNOWN_ERROR);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/all")
    public ResponseEntity<GetWalletsResponse> getWallets(@RequestParam(required = true, defaultValue = "0") int pageId,
            @RequestParam(required = false, defaultValue = "100") int size)
    {
        GetWalletsResponse responses = new GetWalletsResponse();

        try
        {
            List<WalletRecord> wallets = this.service.getWallets(pageId, size);
            if (wallets != null && wallets.size() != 0)
            {
                for (WalletRecord wallet : wallets)
                {
                    GetWalletResponse response = new GetWalletResponse();
                    final String walletId = wallet.getId();
                    try
                    {
                        WalletBalance walletBalance = this.service.getBalance(walletId);

                        Balance balance = new Balance();
                        balance.setEstimated(walletBalance.getEstimated());
                        balance.setAvailable(walletBalance.getAvailable());

                        response.setBalance(balance);
                    }
                    catch (WalletNotFoundException e)
                    {
                        // if wallet is disabled, it won't be in the cache. we don't have to show balance in this case.
                    }
                    response.setCreatedDate(wallet.getCreatedDate());
                    response.setEnabled(wallet.isEnabled());
                    response.setLabel(wallet.getLabel());
                    responses.addWallet(response);

                }
            }

            return new ResponseEntity<>(responses, HttpStatus.OK);
        }
        catch (ServiceNotReadyException e)
        {
            responses.setResultCode(Result.SERVICE_NOT_READY.getCode());
            responses.setResult(Result.SERVICE_NOT_READY);
            return new ResponseEntity<>(responses, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (Throwable e)
        {
            logger.error("failed to get all wallets.", e);
            responses.setResultCode(Result.UNKNOWN_ERROR.getCode());
            responses.setResult(Result.UNKNOWN_ERROR);
            return new ResponseEntity<>(responses, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/{walletId}/address/new")
    public ResponseEntity<GetReceiveAddressResponse> freshReceiveAddress(@PathVariable String walletId,
            @RequestBody GetReceiveAddressRequest request)
    {
        GetReceiveAddressResponse response = new GetReceiveAddressResponse();
        try
        {
            AddressRecord addressRecord = this.service.refreshReceivingAddress(walletId, request.getSymbol(), request.getLabel());
            response.setAddress(addressRecord.getReceiveAddress());
            response.setLabel(addressRecord.getLabel());
            return new ResponseEntity<>(response, HttpStatus.OK);

        }
        catch (InvalidCoinSymbolException e)
        {
            response.setResultCode(Result.INVALID_COIN_SYMBOL.getCode());
            response.setResult(Result.INVALID_COIN_SYMBOL);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (WalletNotFoundException e)
        {
            response.setResultCode(Result.WALLET_NOT_FOUND.getCode());
            response.setResult(Result.WALLET_NOT_FOUND);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (ServiceNotReadyException e)
        {
            response.setResultCode(Result.SERVICE_NOT_READY.getCode());
            response.setResult(Result.SERVICE_NOT_READY);
            return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (Throwable e)
        {
            logger.error("failed to create new receive address.", e);
            response.setResultCode(Result.UNKNOWN_ERROR.getCode());
            response.setResult(Result.UNKNOWN_ERROR);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/{walletId}/send")
    public ResponseEntity<SendCoinResponse> send(@PathVariable String walletId, @RequestBody SendCoinRequest request)
    {
        SendCoinResponse response = new SendCoinResponse();

        try
        {
            String id = service.send(walletId, request.getSymbol(), request.getRecipients(), request.getNumberOfBlock(),
                    request.getMemo(), request.getInternalTransactionId());

            response.setTransactionId(id);

            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (ServiceNotReadyException e)
        {
            response.setResultCode(Result.SERVICE_NOT_READY.getCode());
            response.setResult(Result.SERVICE_NOT_READY);
            return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (WalletNotFoundException e)
        {
            response.setResultCode(Result.WALLET_NOT_FOUND.getCode());
            response.setResult(Result.WALLET_NOT_FOUND);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (InvalidCoinSymbolException e)
        {
            response.setResultCode(Result.INVALID_COIN_SYMBOL.getCode());
            response.setResult(Result.INVALID_COIN_SYMBOL);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (InvalidRecipientException e)
        {
            response.setResultCode(Result.INVALID_RECIPIENT.getCode());
            response.setResult(Result.INVALID_RECIPIENT);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (InsufficientMoneyException e)
        {
            response.setResultCode(Result.INSUFFICIENT_BALANCE.getCode());
            response.setResult(Result.INSUFFICIENT_BALANCE);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        catch (FeeRecordNotFoundException e)
        {
            response.setResultCode(Result.INVALID_FEE_INFORMATION.getCode());
            response.setResult(Result.INVALID_FEE_INFORMATION);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        catch (CryptoException e)
        {
            response.setResultCode(Result.INVALID_CRYPTO_OPERATION.getCode());
            response.setResult(Result.INVALID_CRYPTO_OPERATION);
            return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
        }
        catch (Throwable e)
        {
            logger.error("failed to send coin.", e);
            response.setResultCode(Result.UNKNOWN_ERROR.getCode());
            response.setResult(Result.UNKNOWN_ERROR);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
