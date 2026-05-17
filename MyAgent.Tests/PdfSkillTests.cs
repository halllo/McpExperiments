#pragma warning disable MEAI001, MAAI001
using Microsoft.Agents.AI;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace MyAgent.Tests;

/// <summary>
/// Integration tests that verify the pdf skill scripts are executed correctly.
///
/// Each test is a single RunAsync call where the agent:
///   1. Uses code_interpreter to create a test PDF in the sandbox.
///   2. Uses the pdf skill scripts to analyse the same PDF in the same sandbox session.
///
/// Because both steps run in the same RunAsync the sandbox session is shared,
/// so the file created in step 1 is visible to the scripts in step 2.
/// We assert on the exact output printed by the script to confirm it ran.
/// </summary>
[TestClass]
public sealed class PdfSkillTests
{
    public required TestContext TestContext { get; set; }

    static IServiceProvider BuildServices()
    {
        var host = Program.BuildHost();
        return host.Services;
    }

    static AIAgent CreateAgent(IServiceProvider services) =>Factory.CreateAgent(
        name: "pdf-test", 
        chatClient: Factory.OpenAI(services.GetRequiredService<IConfiguration>(), services), 
        services: services,
        tools: Factory.GetTools());

    /// <summary>
    /// check_fillable_fields.py on a plain text PDF → "does not have fillable form fields"
    /// </summary>
    [TestMethod]
    public async Task CheckFillableFields_ReportsNoFields_ForPlainPdf()
    {
        var agent = CreateAgent(BuildServices());

        var response = await agent.RunAsync("""
            Step 1 – use the code_interpreter tool to run this Python code exactly:

            import subprocess
            subprocess.run(['pip', 'install', 'pypdf', 'pdf2image', '--quiet'], check=True)
            from reportlab.pdfgen import canvas
            c = canvas.Canvas('/tmp/plain.pdf')
            c.drawString(100, 750, 'Hello World')
            c.save()
            print('created /tmp/plain.pdf')

            Step 2 – use the pdf skill to check whether /tmp/plain.pdf has fillable form fields.
            Report the exact message the script printed.
            """, cancellationToken: TestContext.CancellationToken);

        Assert.Contains("does not have fillable form fields", response.Text,
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// check_fillable_fields.py on a PDF with an AcroForm text field → "has fillable form fields"
    /// </summary>
    [TestMethod]
    public async Task CheckFillableFields_ReportsFields_ForAcroFormPdf()
    {
        var agent = CreateAgent(BuildServices());

        var response = await agent.RunAsync("""
            Step 1 – use the code_interpreter tool to run this Python code exactly:

            import subprocess
            subprocess.run(['pip', 'install', 'pypdf', 'pdf2image', '--quiet'], check=True)
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            c = canvas.Canvas('/tmp/form.pdf', pagesize=letter)
            c.drawString(100, 750, 'Form')
            form = c.acroForm
            form.textfield(name='name', tooltip='Name', x=200, y=690, width=200, height=20)
            c.save()
            print('created /tmp/form.pdf')

            Step 2 – use the pdf skill to check whether /tmp/form.pdf has fillable form fields.
            Report the exact message the script printed.
            """, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(
            response.Text.Contains("has fillable form fields", StringComparison.OrdinalIgnoreCase) ||
            response.Text.Contains("have fillable form fields", StringComparison.OrdinalIgnoreCase),
            $"Expected fields-present message in: {response.Text}");
    }

    /// <summary>
    /// extract_form_field_info.py on a two-field form → "Wrote 2 fields to …"
    /// </summary>
    [TestMethod]
    public async Task ExtractFormFieldInfo_WritesCorrectFieldCount()
    {
        var agent = CreateAgent(BuildServices());

        var response = await agent.RunAsync("""
            Step 1 – use the code_interpreter tool to run this Python code exactly:

            import subprocess
            subprocess.run(['pip', 'install', 'pypdf', 'pdf2image', '--quiet'], check=True)
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            c = canvas.Canvas('/tmp/twofields.pdf', pagesize=letter)
            c.drawString(100, 750, 'Form')
            form = c.acroForm
            form.textfield(name='first_name', tooltip='First Name', x=150, y=700, width=200, height=20)
            form.textfield(name='last_name',  tooltip='Last Name',  x=150, y=660, width=200, height=20)
            c.save()
            print('created /tmp/twofields.pdf')

            Step 2 – use the pdf skill to extract the form field information from /tmp/twofields.pdf
            and save it to /tmp/fields.json. Report the exact message the script printed.
            """, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(
            response.Text.Contains("Wrote 2 fields to", StringComparison.OrdinalIgnoreCase) ||
            response.Text.Contains("2 fields", StringComparison.OrdinalIgnoreCase),
            $"Expected 2-fields count in: {response.Text}");
    }

    /// <summary>
    /// convert_pdf_to_images.py on a two-page PDF → "Converted 2 pages to PNG images"
    /// </summary>
    [TestMethod]
    public async Task ConvertPdfToImages_ProducesOneImagePerPage()
    {
        var agent = CreateAgent(BuildServices());

        var response = await agent.RunAsync("""
            Step 1 – use the code_interpreter tool to run this Python code exactly:

            import os, subprocess
            subprocess.run(['pip', 'install', 'pypdf', 'pdf2image', '--quiet'], check=True)
            from reportlab.pdfgen import canvas
            c = canvas.Canvas('/tmp/twopages.pdf')
            c.drawString(100, 750, 'Page One')
            c.showPage()
            c.drawString(100, 750, 'Page Two')
            c.showPage()
            c.save()
            os.makedirs('/tmp/pages', exist_ok=True)
            print('created /tmp/twopages.pdf')

            Step 2 – use the pdf skill to convert /tmp/twopages.pdf to PNG images
            and save them in /tmp/pages/. Report the exact message the script printed.
            """, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(
            response.Text.Contains("Converted 2 pages to PNG images", StringComparison.OrdinalIgnoreCase) ||
            (response.Text.Contains("page_1.png", StringComparison.OrdinalIgnoreCase) &&
             response.Text.Contains("page_2.png", StringComparison.OrdinalIgnoreCase)),
            $"Expected 2-page conversion result in: {response.Text}");
    }
}
#pragma warning restore MEAI001, MAAI001
