mod json_structs;
use anyhow::{Context, Result};
use clap::{command, Parser};
use json_structs::*;
use rust_xlsxwriter::{Color, Format, FormatAlign, FormatBorder, Workbook};

use std::io::Read;
use std::path::PathBuf;
use std::{collections::HashMap, fs::File};

use scraper::{Html, Selector};
use zip::ZipArchive;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// zip格式的扫描报告文件路径
    zip_file: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    get_index_html(cli.zip_file)
}

fn get_index_html(zip_file_path: PathBuf) -> Result<()> {
    let mut xlsx_file_path = zip_file_path.clone();
    let report_system_name = zip_file_path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    xlsx_file_path.set_extension("xlsx");
    let zip_file = File::open(zip_file_path).context("无法读取输入文件")?;
    let mut archive = ZipArchive::new(zip_file).context("无法读取压缩文件")?;
    let mut vul_port_map: HashMap<String, HashMap<u32, VulPort>> = HashMap::new();
    let mut ports_list: Vec<HashMap<String, String>> = Vec::new();
    let mut vuln_list = vec![];
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let path = match file.enclosed_name() {
            Some(path) => path,
            None => {
                println!("Entry {} has a suspicious path", file.name());
                continue;
            }
        };
        // hosts match **/host/*.html
        if file.is_file()
            && path.extension().map_or(false, |ext| ext == "html")
            && path
                .parent()
                .unwrap_or(&path)
                .file_name()
                .map_or(false, |name| name == "host")
        {
            let host_data = parse_html_file(file)?;
            if let Some(Category {
                data: Some(DataUnit {
                    target: Some(ip), .. //extract ip
                }),
                ..
            }) = host_data.get_category_by_name("主机概况")
            {
                if let Some(Category {
                    children: Some(vul_items), //extract (ip, vul, port..)
                    ..
                }) = host_data.get_category_by_name("漏洞信息")
                {
                    let mut port_map = HashMap::new();
                    let vul_items = vul_items.iter().filter_map(|c| c.data.vul_items.as_ref());
                    for vul_item in vul_items {
                        for vuls in vul_item.iter() {
                            for id in vuls.vuls.iter() {
                                let entry = VulPort {
                                    ip: ip.clone(),
                                    vul_id: id.vul_id,
                                    port: vuls.port.unwrap_or(0),
                                    protocol: vuls.protocol.clone(),
                                    service: vuls.service.clone(),
                                };
                                port_map.insert(id.vul_id, entry);
                            }
                        }
                    }
                    let _ = vul_port_map.insert(ip.clone(), port_map);
                }
                if let Some(Category {
                    data: Some(DataUnit{
                        other_info_data: Some(other_info), .. //extract all open ports, services, etc
                    }),
                    ..
                }) = host_data.get_category_by_name("其它信息")
                {
                    if let Some(ports) = other_info.iter().filter(|info|info.info_name.eq("远程端口信息")).map(|info|info.calculate_content_maps()).next(){
                        for mut port_info in ports{
                            port_info.insert(String::from("IP"), ip.clone());
                            ports_list.push(port_info);
                        }
                    }
                }
            }
        }
        // summary match */index.html
        else if file.is_file() && path.ends_with("index.html") {
            let scan_result = parse_html_file(file)?;
            let vuln_category: &Category = scan_result
                .get_category_by_name("漏洞信息")
                .context("无法在汇总表找到漏洞信息结构")?;
            vuln_list = vuln_category
                .children
                .as_ref()
                .and_then(|children| children.first())
                .and_then(|child| child.data.vulns_info.as_ref())
                .context("无法在汇总表找到漏洞信息字段")?
                .vuln_distribution
                .vuln_list
                .clone();
        }
    }
    let vuln_list: Vec<_> = vuln_list
        .iter()
        .flat_map(|v| {
            v.target.iter().map(|ip| {
                let port_info = vul_port_map
                    .get(ip)
                    .and_then(|info| info.get(&v.vul_id))
                    .context("无法在主机详情数据中找到漏洞对应端口")
                    .unwrap();
                ExcelRecord {
                    ip,
                    system_name: &report_system_name,
                    port: port_info.port,
                    protocol: &port_info.protocol,
                    service: &port_info.service,
                    i18n_name: &v.i18n_name,
                    vuln_level: &v.vuln_level,
                    i18n_solution: &v.i18n_solution,
                    i18n_description: &v.i18n_description,
                    cve_id: &v.cve_id,
                }
            })
        })
        .collect();
    write_to_excel(vuln_list, ports_list, &xlsx_file_path.to_string_lossy())
        .context("无法写入xlsx文件")?;
    Ok(())
}

fn parse_html_file<R: Read>(mut html_file: R) -> Result<ScanResult> {
    let mut contents = String::new();
    let _ = html_file.read_to_string(&mut contents);

    // parse html and get json data
    let fragment = Html::parse_fragment(&contents);
    let selector = Selector::parse("script")
        .map_err(|e| anyhow::anyhow!("Failed to parse selector: {:?}", e))?;
    let json_data = fragment
        .select(&selector)
        .next()
        .ok_or_else(|| anyhow::anyhow!("JSON prefix not found"))?;
    let json_data = json_data.inner_html();
    let json_data = json_data
        .strip_prefix("window.data = ")
        .ok_or_else(|| anyhow::anyhow!("Invalid JSON content"))?
        .strip_suffix(';')
        .ok_or_else(|| anyhow::anyhow!("Invalid JSON content"))?;

    // parse json
    Ok(serde_json::from_str(json_data)?)
}

fn write_to_excel(
    vuln_list: Vec<ExcelRecord>,
    ports_list: Vec<HashMap<String, String>>,
    out_path: &str,
) -> Result<()> {
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();
    let _ = worksheet.set_name("系统漏洞");
    let cell_format = Format::new()
        .set_border(FormatBorder::Thin)
        .set_font_name("宋体")
        .set_font_size(10)
        .set_text_wrap()
        .set_align(FormatAlign::Center)
        .set_align(FormatAlign::VerticalCenter);
    let header_format = cell_format
        .clone()
        .set_font_size(12)
        .set_font_color(Color::Red)
        .set_bold();

    // Write header
    worksheet.write_with_format(0, 0, "序号", &header_format)?;
    worksheet.write_with_format(0, 1, "检查单位", &header_format)?;
    worksheet.write_with_format(0, 2, "系统名称", &header_format)?;
    worksheet.write_with_format(0, 3, "主机名", &header_format)?;
    worksheet.write_with_format(0, 4, "IP地址", &header_format)?;
    worksheet.write_with_format(0, 5, "端口", &header_format)?;
    worksheet.write_with_format(0, 6, "协议", &header_format)?;
    worksheet.write_with_format(0, 7, "服务", &header_format)?;
    worksheet.write_with_format(0, 8, "漏洞名称", &header_format)?;
    worksheet.write_with_format(0, 9, "风险分类", &header_format)?;
    worksheet.write_with_format(0, 10, "风险等级", &header_format)?;
    worksheet.write_with_format(0, 11, "整改建议", &header_format)?;
    worksheet.write_with_format(0, 12, "漏洞描述", &header_format)?;
    worksheet.write_with_format(0, 13, "漏洞CVE编号", &header_format)?;

    let _ = worksheet.set_freeze_panes(1, 0);
    let _ = worksheet.autofilter(0, 0, 1, 13);

    let _ = worksheet.set_row_height(0, 40);
    let _ = worksheet.set_column_width(0, 6);
    let _ = worksheet.set_column_width(1, 6);
    let _ = worksheet.set_column_width(2, 28);
    let _ = worksheet.set_column_width(3, 8);
    let _ = worksheet.set_column_width(4, 16);
    let _ = worksheet.set_column_width(5, 8);
    let _ = worksheet.set_column_width(6, 8);
    let _ = worksheet.set_column_width(7, 8);
    let _ = worksheet.set_column_width(8, 45);
    let _ = worksheet.set_column_width(9, 8);
    let _ = worksheet.set_column_width(10, 8);
    let _ = worksheet.set_column_width(11, 45);
    let _ = worksheet.set_column_width(12, 45);
    let _ = worksheet.set_column_width(13, 13);

    for (i, data) in vuln_list.iter().enumerate() {
        let row_num: u32 = (i + 1).try_into().context("写入Excel索引溢出")?;
        let _ = worksheet.set_row_height(row_num, 25);
        worksheet.write_with_format(row_num, 0, row_num, &cell_format)?;
        worksheet.write_with_format(row_num, 1, "1", &cell_format)?;
        worksheet.write_with_format(row_num, 2, data.system_name, &cell_format)?;
        worksheet.write_with_format(row_num, 3, "", &cell_format)?;
        worksheet.write_with_format(row_num, 4, data.ip, &cell_format)?;
        worksheet.write_with_format(row_num, 5, data.port, &cell_format)?;
        worksheet.write_with_format(row_num, 6, data.protocol, &cell_format)?;
        worksheet.write_with_format(row_num, 7, data.service, &cell_format)?;
        worksheet.write_with_format(row_num, 8, data.i18n_name, &cell_format)?;
        worksheet.write_with_format(row_num, 9, "漏洞", &cell_format)?;
        worksheet.write_with_format(row_num, 10, data.vuln_level, &cell_format)?;
        worksheet.write_with_format(row_num, 11, data.i18n_solution, &cell_format)?;
        worksheet.write_with_format(row_num, 12, data.i18n_description, &cell_format)?;
        worksheet.write_with_format(row_num, 13, data.cve_id, &cell_format)?;
    }

    let worksheet = workbook.add_worksheet();
    let _ = worksheet.set_name("端口信息");
    let cell_format = Format::new()
        .set_border(FormatBorder::Thin)
        .set_font_name("宋体")
        .set_font_size(10)
        .set_text_wrap()
        .set_align(FormatAlign::Center)
        .set_align(FormatAlign::VerticalCenter);
    let header_format = cell_format
        .clone()
        .set_font_size(12)
        .set_font_color(Color::Red)
        .set_bold();

    // Write header
    worksheet.write_with_format(0, 0, "IP", &header_format)?;
    worksheet.write_with_format(0, 1, "端口", &header_format)?;
    worksheet.write_with_format(0, 2, "协议", &header_format)?;
    worksheet.write_with_format(0, 3, "服务", &header_format)?;
    worksheet.write_with_format(0, 4, "状态", &header_format)?;

    let _ = worksheet.set_freeze_panes(1, 0);
    let _ = worksheet.autofilter(0, 0, 1, 4);

    let _ = worksheet.set_row_height(0, 40);
    let _ = worksheet.set_column_width(0, 16);
    let _ = worksheet.set_column_width(1, 6);
    let _ = worksheet.set_column_width(2, 6);
    let _ = worksheet.set_column_width(3, 16);
    let _ = worksheet.set_column_width(4, 8);

    let invalid_string = String::from("--");
    for (i, data) in ports_list.iter().enumerate() {
        let row_num: u32 = (i + 1).try_into().context("写入Excel索引溢出")?;
        let _ = worksheet.set_row_height(row_num, 25);
        worksheet.write_with_format(
            row_num,
            0,
            data.get("IP").unwrap_or(&invalid_string),
            &cell_format,
        )?;
        worksheet.write_with_format(
            row_num,
            1,
            data.get("端口").unwrap_or(&invalid_string),
            &cell_format,
        )?;
        worksheet.write_with_format(
            row_num,
            2,
            data.get("协议").unwrap_or(&invalid_string),
            &cell_format,
        )?;
        worksheet.write_with_format(
            row_num,
            3,
            data.get("服务").unwrap_or(&invalid_string),
            &cell_format,
        )?;
        worksheet.write_with_format(
            row_num,
            4,
            data.get("状态").unwrap_or(&invalid_string),
            &cell_format,
        )?;
    }
    let _ = workbook.save(out_path);
    Ok(())
}
