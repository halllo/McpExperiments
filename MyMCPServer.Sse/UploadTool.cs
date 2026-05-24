using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using System.ComponentModel;
using System.Text;

namespace MyMCPServer.Sse
{
	[McpServerToolType]
	public class UploadTool
	{
		/// <summary>Supported content types and the extension each maps to.</summary>
		private static readonly IReadOnlyDictionary<string, string> SupportedTypes =
			new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
			{
				["application/pdf"] = ".pdf",
				["text/plain"] = ".txt",
				["text/markdown"] = ".md",
				["text/x-markdown"] = ".md",
			};

		private readonly ILogger<UploadTool> logger;
		private readonly IWebHostEnvironment env;

		public UploadTool(ILogger<UploadTool> logger, IWebHostEnvironment env)
		{
			this.logger = logger;
			this.env = env;
		}

		[McpServerTool, Description(
			"Uploads a file and stores it on disk. " +
			"Supported content types: application/pdf, text/plain, text/markdown. " +
			"Returns the saved file name and size.")]
		public IEnumerable<ContentBlock> Upload(
			[Description("The raw file bytes (base64-encoded in transit).")] byte[] file,
			[Description("The original file name, e.g. 'report.pdf' or 'notes.md'.")] string fileName,
			[Description("MIME content type: 'application/pdf', 'text/plain', or 'text/markdown'.")] string contentType)
		{
			if (file is not { Length: > 0 })
				throw new McpException("File content must not be empty.");

			// Resolve the canonical extension for this content type.
			if (!SupportedTypes.TryGetValue(contentType, out var ext))
				throw new McpException(
					$"Unsupported content type '{contentType}'. " +
					$"Supported: {string.Join(", ", SupportedTypes.Keys)}.");

			// Type-specific content validation.
			ValidateContent(file, ext);

			// Sanitise the caller-supplied file name; never trust it for path construction.
			var safeName = Path.GetFileName(fileName.Trim());
			if (string.IsNullOrEmpty(safeName))
				safeName = $"upload{ext}";

			// Normalise the extension so it always matches the declared content type.
			var stem = Path.GetFileNameWithoutExtension(safeName);
			var unique = $"{stem}_{DateTime.UtcNow:yyyyMMddHHmmssfff}{ext}";

			var uploadsDir = Path.Combine(env.ContentRootPath, "uploads");
			Directory.CreateDirectory(uploadsDir);
			var fullPath = Path.Combine(uploadsDir, unique);

			if (ext == ".pdf")
				File.WriteAllBytes(fullPath, file);
			else
				File.WriteAllText(fullPath, Encoding.UTF8.GetString(file), Encoding.UTF8);

			logger.LogInformation("Saved upload {FileName} ({Bytes} bytes, {ContentType}) to {Dir}", unique, file.Length, contentType, uploadsDir);

			return
			[
				new TextContentBlock
				{
					Text = $"Uploaded '{unique}' ({file.Length:N0} bytes)."
				}
			];
		}

		private static void ValidateContent(byte[] file, string ext)
		{
			switch (ext)
			{
				case ".pdf":
					// Check %PDF magic bytes
					if (file.Length < 4 || file[0] != 0x25 || file[1] != 0x50 || file[2] != 0x44 || file[3] != 0x46)
						throw new McpException("File does not appear to be a valid PDF (missing %PDF header).");
					break;

				case ".txt":
				case ".md":
					// Verify the bytes are valid UTF-8 text.
					try
					{
						Encoding.UTF8.GetString(file); // throws DecoderFallbackException if invalid
					}
					catch (Exception ex)
					{
						throw new McpException($"File content is not valid UTF-8 text: {ex.Message}");
					}
					break;
			}
		}
	}
}
