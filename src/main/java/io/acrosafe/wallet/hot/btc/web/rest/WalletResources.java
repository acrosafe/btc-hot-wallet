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
            WalletRecord record = this.service.createWallet(request.getSymbol(), request.getLabel(), request.getEnabled(),
                    request.getForwardAddress());
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
