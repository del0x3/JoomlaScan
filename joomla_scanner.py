#!/usr/bin/env python3
"""
Modern Joomla Scanner
A fast and efficient Joomla CMS vulnerability scanner
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Dict
from urllib.parse import urljoin, urlparse

import httpx
import typer
from bs4 import BeautifulSoup
from pydantic import BaseModel, HttpUrl, Field
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

logger = logging.getLogger("joomla_scanner")
console = Console()

class ScanConfig(BaseModel):
    """Configuration for the scanner"""
    url: HttpUrl
    threads: int = Field(default=10, ge=1, le=50, description="Number of concurrent threads")
    timeout: float = Field(default=5.0, ge=1, le=30, description="Request timeout in seconds")
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    verify_ssl: bool = Field(default=False, description="Verify SSL certificates")
    max_retries: int = Field(default=3, ge=1, le=5, description="Maximum number of retries for failed requests")
    output_file: Optional[str] = Field(default=None, description="File to save scan results")

class Vulnerability(BaseModel):
    """Represents a vulnerability"""
    type: str
    description: str
    severity: str
    url: str

class Component(BaseModel):
    """Represents a Joomla component"""
    name: str
    paths: Set[str]
    vulnerabilities: List[Vulnerability] = []
    version: Optional[str] = None
    last_modified: Optional[datetime] = None

class ScanResult(BaseModel):
    """Represents the complete scan result"""
    target_url: HttpUrl
    scan_time: datetime
    duration: float
    components: List[Component]
    total_vulnerabilities: int
    scan_config: ScanConfig

class Scanner:
    """Main scanner class"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.components: List[Component] = []
        self.session: Optional[httpx.AsyncClient] = None
        self.headers = {"User-Agent": config.user_agent}
        self.start_time: Optional[datetime] = None
        
    async def __aenter__(self):
        self.session = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            headers=self.headers,
            verify=self.config.verify_ssl,
            follow_redirects=True
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()
            
    async def check_url(self, url: str, retry_count: int = 0) -> Optional[int]:
        """Check if URL exists and return status code with retry logic"""
        try:
            response = await self.session.get(url)
            return response.status_code
        except httpx.RequestError:
            if retry_count < self.config.max_retries:
                await asyncio.sleep(1)  # Exponential backoff
                return await self.check_url(url, retry_count + 1)
            return None

    async def check_directory_listing(self, url: str) -> bool:
        """Check if directory listing is enabled"""
        try:
            response = await self.session.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            return bool(soup.find("title", string=lambda x: x and "Index of" in x))
        except Exception:
            return False

    async def check_readme_files(self, url: str) -> bool:
        """Check for exposed README files"""
        readme_paths = ["README.txt", "readme.txt", "README.md", "readme.md"]
        for path in readme_paths:
            full_url = urljoin(url, path)
            if await self.check_url(full_url) == 200:
                return True
        return False

    async def check_manifest_files(self, url: str) -> bool:
        """Check for exposed manifest files"""
        manifest_paths = ["MANIFEST.xml", "manifest.xml"]
        for path in manifest_paths:
            full_url = urljoin(url, path)
            if await self.check_url(full_url) == 200:
                return True
        return False
            
    async def check_component(self, component: str) -> Optional[Component]:
        """Check a single component for vulnerabilities"""
        paths = [
            f"/components/{component}/",
            f"/administrator/components/{component}/",
            f"/index.php?option={component}"
        ]
        
        found_paths = set()
        vulnerabilities = []
        version = None
        last_modified = None
        
        for path in paths:
            url = urljoin(str(self.config.url), path)
            status = await self.check_url(url)
            
            if status == 200:
                found_paths.add(path)
                
                # Check for common vulnerabilities
                if await self.check_directory_listing(url):
                    vulnerabilities.append(Vulnerability(
                        type="Directory Listing",
                        description="Directory listing is enabled, exposing sensitive information",
                        severity="Medium",
                        url=url
                    ))
                    
                if await self.check_readme_files(url):
                    vulnerabilities.append(Vulnerability(
                        type="Exposed Documentation",
                        description="README files are exposed, revealing component information",
                        severity="Low",
                        url=url
                    ))
                    
                if await self.check_manifest_files(url):
                    vulnerabilities.append(Vulnerability(
                        type="Exposed Manifest",
                        description="Manifest files are exposed, revealing component details",
                        severity="Low",
                        url=url
                    ))
                    
                # Try to get version information
                version = await self.get_component_version(url)
                last_modified = await self.get_last_modified(url)
                    
        if found_paths:
            return Component(
                name=component,
                paths=found_paths,
                vulnerabilities=vulnerabilities,
                version=version,
                last_modified=last_modified
            )
        return None
        
    async def get_component_version(self, url: str) -> Optional[str]:
        """Try to extract component version from various sources"""
        try:
            response = await self.session.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Check for version in meta tags
            version_meta = soup.find("meta", {"name": "generator"})
            if version_meta:
                return version_meta.get("content")
                
            # Check for version in manifest
            manifest_url = urljoin(url, "manifest.xml")
            if await self.check_url(manifest_url) == 200:
                manifest_response = await self.session.get(manifest_url)
                manifest_soup = BeautifulSoup(manifest_response.text, "xml")
                version_tag = manifest_soup.find("version")
                if version_tag:
                    return version_tag.text
                    
        except Exception:
            pass
        return None
        
    async def get_last_modified(self, url: str) -> Optional[datetime]:
        """Get last modified date of the component"""
        try:
            response = await self.session.head(url)
            if "last-modified" in response.headers:
                return datetime.strptime(response.headers["last-modified"], "%a, %d %b %Y %H:%M:%S %Z")
        except Exception:
            pass
        return None
        
    async def scan(self):
        """Main scanning method with parallel scanning"""
        self.start_time = datetime.now()
        
        # Load components from database
        components_db = self.load_components_db()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning components...", total=len(components_db))
            
            # Create chunks of components for parallel scanning
            chunk_size = self.config.threads
            for i in range(0, len(components_db), chunk_size):
                chunk = components_db[i:i + chunk_size]
                tasks = [self.check_component(comp) for comp in chunk]
                results = await asyncio.gather(*tasks)
                
                for result in results:
                    if result:
                        self.components.append(result)
                    progress.advance(task)
                    
    def load_components_db(self) -> List[str]:
        """Load components from database file"""
        db_path = Path("comptotestdb.txt")
        if not db_path.exists():
            logger.error("Components database not found!")
            return []
            
        with open(db_path) as f:
            return [line.strip() for line in f if line.strip()]
            
    def generate_report(self) -> ScanResult:
        """Generate a complete scan report"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        return ScanResult(
            target_url=self.config.url,
            scan_time=self.start_time,
            duration=duration,
            components=self.components,
            total_vulnerabilities=sum(len(c.vulnerabilities) for c in self.components),
            scan_config=self.config
        )
        
    def save_report(self, report: ScanResult):
        """Save scan report to file if specified"""
        if self.config.output_file:
            with open(self.config.output_file, "w") as f:
                f.write(report.json(indent=2))
            logger.info(f"Report saved to {self.config.output_file}")

def display_results(report: ScanResult):
    """Display scan results in a rich format"""
    console.print(Panel.fit(
        "[bold blue]Joomla Scanner Results[/bold blue]",
        border_style="blue"
    ))
    
    # Summary table
    summary_table = Table(title="Scan Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="green")
    
    summary_table.add_row("Target URL", str(report.target_url))
    summary_table.add_row("Scan Time", report.scan_time.strftime("%Y-%m-%d %H:%M:%S"))
    summary_table.add_row("Duration", f"{report.duration:.2f} seconds")
    summary_table.add_row("Components Found", str(len(report.components)))
    summary_table.add_row("Total Vulnerabilities", str(report.total_vulnerabilities))
    
    console.print(summary_table)
    
    # Components table
    if report.components:
        components_table = Table(title="Found Components")
        components_table.add_column("Component", style="cyan")
        components_table.add_column("Version", style="green")
        components_table.add_column("Vulnerabilities", style="red")
        components_table.add_column("Paths", style="yellow")
        
        for component in report.components:
            components_table.add_row(
                component.name,
                component.version or "Unknown",
                str(len(component.vulnerabilities)),
                "\n".join(component.paths)
            )
            
        console.print(components_table)
        
        # Detailed vulnerabilities
        if report.total_vulnerabilities > 0:
            vuln_table = Table(title="Vulnerabilities")
            vuln_table.add_column("Component", style="cyan")
            vuln_table.add_column("Type", style="red")
            vuln_table.add_column("Severity", style="yellow")
            vuln_table.add_column("Description", style="white")
            vuln_table.add_column("URL", style="blue")
            
            for component in report.components:
                for vuln in component.vulnerabilities:
                    vuln_table.add_row(
                        component.name,
                        vuln.type,
                        vuln.severity,
                        vuln.description,
                        vuln.url
                    )
                    
            console.print(vuln_table)
    else:
        console.print("\n[bold red]No components found![/bold red]")

async def run_scanner(config: ScanConfig):
    """Run the scanner with proper async context management"""
    async with Scanner(config) as scanner:
        await scanner.scan()
        return scanner.generate_report()

def main(
    url: str = typer.Argument(..., help="The Joomla URL/domain to scan"),
    threads: int = typer.Option(10, help="Number of concurrent threads"),
    timeout: float = typer.Option(5.0, help="Request timeout in seconds"),
    verify_ssl: bool = typer.Option(False, help="Verify SSL certificates"),
    max_retries: int = typer.Option(3, help="Maximum number of retries for failed requests"),
    output_file: Optional[str] = typer.Option(None, help="File to save scan results")
):
    """Main entry point"""
    try:
        config = ScanConfig(
            url=url,
            threads=threads,
            timeout=timeout,
            verify_ssl=verify_ssl,
            max_retries=max_retries,
            output_file=output_file
        )
        
        # Run the scanner
        report = asyncio.run(run_scanner(config))
        
        # Display results
        display_results(report)
        
        # Save report if requested
        if output_file:
            with open(output_file, "w") as f:
                f.write(report.json(indent=2))
            logger.info(f"Report saved to {output_file}")
            
    except Exception as e:
        logger.exception("An error occurred during scanning")
        raise typer.Exit(1)

if __name__ == "__main__":
    typer.run(main) 