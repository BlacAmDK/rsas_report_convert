use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub categories: Vec<Category>,
    pub task_type: u8,
    pub create_time: String,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Category {
    pub title: String,
    pub children: Option<Vec<Child>>,
    pub data: Option<DataUnit>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Child {
    pub data: DataUnit,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct DataUnit {
    // summary
    pub vulns_info: Option<VulnsInfo>,
    // host
    pub vul_items: Option<Vec<VulItem>>,
    pub target: Option<String>,
    // other_info(ports)
    pub other_info_data: Option<Vec<OtherInfo>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VulnsInfo {
    pub vuln_distribution: VulnDistribution,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct VulnDistribution {
    pub vuln_list: Vec<Vuln>,
    pub hosts_count: u32,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Vuln {
    pub vul_id: u32,
    #[serde(deserialize_with = "deserialize_cve")]
    pub cve_id: String,
    pub i18n_name: String,
    #[serde(deserialize_with = "deserialize_description")]
    pub i18n_description: String,
    #[serde(deserialize_with = "deserialize_solution")]
    pub i18n_solution: String,
    pub date_found: String,
    pub date_recorded: String,
    #[serde(deserialize_with = "deserialize_target")]
    pub target: Vec<String>,
    #[serde(deserialize_with = "deserialize_level")]
    pub vuln_level: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VulItem {
    #[serde(deserialize_with = "deserialize_port")]
    pub port: Option<u16>,
    pub service: String,
    pub protocol: String,
    pub vuls: Vec<Vul>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Vul {
    pub vul_id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VulPort {
    pub ip: String,
    pub vul_id: u32,
    pub port: u16,
    pub protocol: String,
    pub service: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct OtherInfo {
    pub info_name: String,
    pub column_names: Vec<String>,
    pub content: Vec<Vec<String>>,
}
#[derive(Debug)]
pub struct ExcelRecord<'a> {
    pub ip: &'a String,
    pub system_name: &'a String,
    pub port: u16,
    pub protocol: &'a String,
    pub service: &'a String,
    pub i18n_name: &'a String,
    pub vuln_level: &'a String,
    pub i18n_solution: &'a String,
    pub i18n_description: &'a String,
    pub cve_id: &'a String,
}

fn deserialize_target<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value: String = Deserialize::deserialize(deserializer)?;
    Ok(value.split(';').map(|s| s.trim().to_string()).collect())
}
fn deserialize_level<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value: String = Deserialize::deserialize(deserializer)?;
    Ok(value
        .replace("high", "高")
        .replace("middle", "中")
        .replace("low", "低"))
}
fn deserialize_cve<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value: String = Deserialize::deserialize(deserializer)?;
    Ok(if value.is_empty() {
        "漏洞暂无CVE编号".to_string()
    } else {
        value
    })
}
fn deserialize_description<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Vec<String> = Deserialize::deserialize(deserializer)?;
    Ok(value.join("\n"))
}
fn deserialize_solution<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Vec<String> = Deserialize::deserialize(deserializer)?;
    Ok(value.join("\n"))
}

fn deserialize_port<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Ok(value) = Deserialize::deserialize(deserializer) {
        Ok(Some(value))
    } else {
        Ok(None)
    }
}
impl OtherInfo {
    pub fn calculate_content_maps(&self) -> Vec<HashMap<String, String>> {
        let mut content_maps = Vec::new();
        let hashmap_len = self.content.len();
        for mut content_item in self.content.clone() {
            let mut hashmap = HashMap::with_capacity(hashmap_len);
            for header in self.column_names.iter().rev() {
                hashmap.insert(
                    header.clone(),
                    content_item
                        .pop()
                        .unwrap_or_else(|| "Parse Error!".to_string()),
                );
            }
            content_maps.push(hashmap);
        }
        content_maps
    }
}

impl ScanResult {
    pub fn get_category_by_name(&self, name: &str) -> Option<&Category> {
        let matched_categories = self
            .categories
            .iter()
            .filter(|c| c.title.eq(name))
            .collect::<Vec<&Category>>();
        if matched_categories.len() == 1 {
            Some(matched_categories[0])
        } else {
            None
        }
    }
}
