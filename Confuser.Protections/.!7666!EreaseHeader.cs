using Confuser.Core;
using Confuser.Core.Helpers;
using Confuser.Core.Services;
using Confuser.Renamer;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Collections.Generic;
using System.Linq;

namespace Confuser.Protections
{
    internal class EraseHeadersProtection : Protection
    {
        protected override void Initialize(ConfuserContext context)
        {
        }

        protected override void PopulatePipeline(ProtectionPipeline pipeline)
        {
            pipeline.InsertPreStage(PipelineStage.EndModule, new EraseHeadersProtection.ErasePhase(this));
        }

