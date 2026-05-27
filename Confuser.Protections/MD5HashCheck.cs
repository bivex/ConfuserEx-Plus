using Confuser.Core;
using Confuser.Core.Helpers;
using Confuser.Core.Services;
using Confuser.Renamer;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Confuser.Protections
{
    [BeforeProtection("Ki.ControlFlow")]
    internal class MD5HashCheck : Protection
    {
        public const string _Id = "md5 hash check";
        public const string _FullId = "Ki.md5";
        public ModuleWriterListener CurrentListener = new ModuleWriterListener();
        
        public override string Name
        {
            get { return "Integrity Hash Check"; }
        }

        public override string Description
        {
            get { return "Prevents file modification by validating HMAC-SHA256 integrity."; }
        }

        public override string Id
        {
            get { return _Id; }
        }

        public override string FullId
        {
            get { return _FullId; }
        }

        public override ProtectionPreset Preset
        {
            get { return ProtectionPreset.Basic; }
        }

        protected override void Initialize(ConfuserContext context) { }

        protected override void PopulatePipeline(ProtectionPipeline pipeline)
        {
            pipeline.InsertPreStage(PipelineStage.ProcessModule, new MD5HashPhase(this));
        }

        class MD5HashPhase : ProtectionPhase
        {
            public MD5HashPhase(MD5HashCheck parent) : base(parent) { }

            public override ProtectionTargets Targets
            {
                get { return ProtectionTargets.Modules; }
            }

            public override string Name
            {
                get { return "Integrity Hash Injection"; }
            }

            protected override void Execute(ConfuserContext context, ProtectionParameters parameters)
            {
                TypeDef rtType = context.Registry.GetService<IRuntimeService>().GetRuntimeType("Confuser.Runtime.MD5");

                var marker = context.Registry.GetService<IMarkerService>();
                var name = context.Registry.GetService<INameService>();
                context.CurrentModuleWriterListener.OnWriterEvent += InjectHash;
                
                foreach (ModuleDef module in parameters.Targets.OfType<ModuleDef>())
                {
                    IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, module.GlobalType, module);

                    MethodDef cctor = module.GlobalType.FindStaticConstructor();
                    var init = (MethodDef)members.Single(method => method.Name == "Initialize");
                    cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));
                    
                    foreach (IDnlibDef member in members)
                        name.MarkHelper(member, marker, (Protection)Parent);
                }
            }

            static string Hash(byte[] hash)
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] salt = Encoding.ASCII.GetBytes("NeonVM_S@lt_2026_Secure_Hash");
                    byte[] combined = new byte[hash.Length + salt.Length];
                    System.Buffer.BlockCopy(hash, 0, combined, 0, hash.Length);
                    System.Buffer.BlockCopy(salt, 0, combined, hash.Length, salt.Length);

                    byte[] btr = sha256.ComputeHash(combined);
                    StringBuilder sb = new StringBuilder();
                    foreach (byte ba in btr)
                    {
                        sb.Append(ba.ToString("x2").ToLower());
                    }
                    return sb.ToString(); // SHA256 hex is exactly 64 chars
                }
            }

            void InjectHash(object sender, ModuleWriterListenerEventArgs e)
            {
                var writer = (ModuleWriterBase)sender;
                if (e.WriterEvent == ModuleWriterEvent.End)
                {
                    var st = new StreamReader(writer.DestinationStream);
                    var a = new BinaryReader(st.BaseStream);
                    a.BaseStream.Position = 0;
                    
                    // Read the entire generated PE file
                    var data = a.ReadBytes((int)(st.BaseStream.Length));
                    var enc = Encoding.ASCII.GetBytes(Hash(data));
                    
                    // Safely append the 64-byte signature to the end
                    writer.DestinationStream.Position = writer.DestinationStream.Length;
                    writer.DestinationStream.Write(enc, 0, enc.Length);
                }
            }
        }
    }
}