﻿/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// LsarLookupSids Response (opnum 15)
/// </summary>
public class LsarLookupSidsResponse
{
    public LsaReferencedDomainList DomainList;
    public LsaTranslatedArray<LsaTranslatedName> TranslatedSids;
    public uint Count;

    public LsarLookupSidsResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);

        parser.BeginStructure();
        parser.ReadEmbeddedStructureFullPointer(ref DomainList);
        parser.EndStructure();

        TranslatedSids = new LsaTranslatedArray<LsaTranslatedName>();
        parser.ReadStructure(TranslatedSids);

        Count = parser.ReadUInt32();

        parser.EndStructure();
    }
}