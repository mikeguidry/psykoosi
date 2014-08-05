#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include <string.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;
using namespace pe_win;


//Пример, показывающий, как добавить секцию в PE-файл и записать в нее какие-нибудь данные
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: section_adder.exe PE_FILE" << std::endl;
		return 0;
	}

	//Открываем файл
	std::ifstream pe_file(argv[1], std::ios::in | std::ios::binary);
	if(!pe_file)
	{
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		//Создаем экземпляр PE или PE+ класса с помощью фабрики
		pe_base image(pe_factory::create_pe(pe_file));
		int amount_of_imports = 0;
		//Проверим, есть ли импорты у файла
		if(!image.has_imports())
		{
			std::cout << "Image has no imports" << std::endl;
			return 0;
		}

		std::cout << "Reading PE imports..." << std::hex << std::showbase << std::endl << std::endl;

		//Получаем список импортируемых библиотек с функциями
		const imported_functions_list imports = get_imported_functions(image);

		//Перечисляем импортированные библиотеки и выводим информацию о них
		for(imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it)
		{
			const import_library& lib = *it; //Импортируемая библиотека
			std::cout << "Library [" << lib.get_name() << "]" << std::endl //Имя
				<< "Timestamp: " << lib.get_timestamp() << std::endl //Временная метка
				<< "RVA to IAT: " << lib.get_rva_to_iat() << std::endl //Относительный адрес к import address table
				<< "========" << std::endl;

			//Перечисляем импортированные функции для библиотеки
			const import_library::imported_list& functions = lib.get_imported_functions();
			for(import_library::imported_list::const_iterator func_it = functions.begin(); func_it != functions.end(); ++func_it)
			{
				const imported_function& func = *func_it; //Импортированная функция
				std::cout << "[+] ";
				if(func.has_name()) //Если функция имеет имя - выведем его
					std::cout << func.get_name();
				else
					std::cout << "#" << func.get_ordinal(); //Иначе она импортирована по ординалу

				//Хинт
				std::cout << " hint: " << func.get_hint() << std::endl;
				
				amount_of_imports++;
			}

			std::cout << std::endl;
		}
		
		std::cout << "Reading PE sections..." << std::hex << std::showbase << std::endl << std::endl;
		const section_list sections(image.get_image_sections());



		char *code_ptr = NULL;
		std::string section_data;
		//Перечисляем секции и выводим информацию о них
		for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it)
		{
			const section &s = *it;
			std::cout << "Section [" << s.get_name() << "]" << std::endl //Имя секции
				<< "Characteristics: " << s.get_characteristics() << std::endl //Характеристики
				<< "Size of raw data: " << s.get_size_of_raw_data() << std::endl //Размер данных в файле
				<< "Virtual address: " << s.get_virtual_address() << std::endl //Виртуальный адрес
				<< "Virtual size: " << s.get_virtual_size() << std::endl //Виртуальный размер
				<< " Raw Data Size: " << s.get_size_of_raw_data() << std::endl
				<< std::endl;
				

				if (s.get_name() == std::string(".text")) {
				  std::cout << "Found code!" << std::endl;
				  section_data = s.get_raw_data();
				  section_data.resize(s.get_virtual_size());
					code_ptr = (char *)section_data.c_str();
				}
		}
		
		printf("code at %p\n", code_ptr);
for (int a = 0; a < 4096; a++) { printf("%02X", (unsigned char)code_ptr[a]); if (!(a%16)) puts("\n"); }
puts("\n");

		//Секцию можно добавить только после всех существующих, чтобы PE-файл не испортился
		//Создаем новую секцию
		section new_section;
		new_section.readable(true).writeable(true); //Делаем секцию доступной для чтения и записи
		new_section.set_name(".proxy"); //Ставим имя секции - максимум 8 символов
		
		int aligned_size = amount_of_imports * sizeof(unsigned long);
		int missing = aligned_size % image.get_section_alignment();
		if (missing) aligned_size += missing;
		
		new_section.set_size_of_raw_data(aligned_size); //Устанавливаем данные секции
		new_section.set_virtual_size(aligned_size);
		std::string o;
		o = "";
		for (int i = 0; i < aligned_size; i++) o += "0";
		new_section.set_raw_data(o);
		new_section.set_characteristics(0x40000040);
		

		//Добавляем секцию. Все адреса пересчитаются автоматически
		//Вызов вернет ссылку на уже добавленную секцию с пересчитанными адресами
		//Совсем пустую секцию к образу добавить нельзя, у нее должен быть ненулевой размер данных или виртуальный размер
		section& added_section = image.add_section(new_section);

		//Если нужно изменить виртуальный размер секции, то делается это так:
		image.set_section_virtual_size(added_section, 0x1000);
		
		//Создаем новый PE-файл
		std::string base_file_name(argv[1]);
		std::string::size_type slash_pos;
		if((slash_pos = base_file_name.find_last_of("/\\")) != std::string::npos)
			base_file_name = base_file_name.substr(slash_pos + 1);

		base_file_name = "new_" + base_file_name;
		std::ofstream new_pe_file(base_file_name.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
		if(!new_pe_file)
		{
			std::cout << "Cannot create " << base_file_name << std::endl;
			return -1;
		}

		//Пересобираем PE-файл
		rebuild_pe(image, new_pe_file);

		std::cout << "PE was rebuilt and saved to " << base_file_name << std::endl;
	}
	catch(const pe_exception& e)
	{
		//Если возникла ошибка
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}

