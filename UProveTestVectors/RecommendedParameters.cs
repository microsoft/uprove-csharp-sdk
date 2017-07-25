//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//    This code is licensed under the Apache License
//    Version 2.0.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

using UProveParams;

namespace UProveTestVectors
{
    class RecommendedParameters
    {
        static public ECRecommendedParameters.ECParams P256 = ECRecommendedParameters.ecParams[(int)ECRecommendedParameters.CurveNames.P256];
        static public SubgroupRecommendedParameters.SGParams L2048N256 = SubgroupRecommendedParameters.sgParams[(int)SubgroupRecommendedParameters.SGNames.L2048N256];
    }
}
